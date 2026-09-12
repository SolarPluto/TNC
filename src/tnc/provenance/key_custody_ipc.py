"""Authenticated loopback TEST IPC. No OS peer-identity or durable broker claim."""
import hmac
from hashlib import sha256
import secrets
import socket
import struct
from time import monotonic
from typing import Literal

from pydantic import Field
from tnc.provenance.authorization_models import Model, Digest, Identifier, canonical_bytes, decode_canonical, record_digest
from tnc.provenance.key_custody_logic import CustodySignRequest, evaluate_custody_request
from tnc.provenance.key_custody_provider import TestCustodyProvider
from tnc.provenance.reconciliation_verifier import SignedObservation

MAX_FRAME = 32768
MAX_TOKENS = 64
DOMAIN = b'TNC-CUSTODY-IPC-v1:'


class IPCRequest(Model):
    action: Literal['ISSUE', 'SIGN', 'RECOVER']
    request_digest: Digest
    request: CustodySignRequest | None = None
    token: str = Field(default='', strict=True, max_length=129)
    budget_ms: int = Field(default=5000, strict=True, ge=1, le=5000)


class IPCResult(Model):
    status: Identifier
    token: str = Field(default='', strict=True, max_length=129)
    outcome: str = Field(default='', strict=True, max_length=128)
    response: SignedObservation | None = None


class _Hello(Model):
    nonce: Digest


class _Packet(Model):
    principal: Identifier
    body_hex: str = Field(strict=True, max_length=MAX_FRAME, pattern=r'^[0-9a-f]+$')
    mac: Digest


def _mac(secret, kind, nonce, principal, body):
    # Canonical typed packet fields plus a fixed domain/direction prevent ambiguity.
    prefix = canonical_bytes(_Hello(nonce=nonce))
    return hmac.new(secret, DOMAIN + kind + prefix + len(principal.encode()).to_bytes(4,'big')
                    + principal.encode() + body, sha256).hexdigest()


def _timeout(sock, deadline):
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError('IPC deadline')
    sock.settimeout(remaining)


def _read(sock, count, deadline):
    result = bytearray()
    while len(result) < count:
        _timeout(sock, deadline)
        data = sock.recv(count-len(result))
        if not data:
            raise ConnectionError('Incomplete IPC frame')
        result.extend(data)
    return bytes(result)


def receive_frame(sock, deadline):
    count = struct.unpack('!I', _read(sock,4,deadline))[0]
    if not 1 <= count <= MAX_FRAME:
        raise ValueError('IPC frame size')
    return _read(sock,count,deadline)


def send_frame(sock, raw, deadline):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_FRAME:
        raise ValueError('IPC frame size')
    view = memoryview(struct.pack('!I',len(raw))+raw)
    while view:
        _timeout(sock,deadline)
        sent = sock.send(view)
        if not sent:
            raise ConnectionError('Incomplete IPC frame')
        view = view[sent:]


def _packet(principal, body, secret, nonce, direction):
    return canonical_bytes(_Packet(principal=principal, body_hex=body.hex(),
        mac=_mac(secret,direction,nonce,principal,body)))


def _unpack(raw, secret, nonce, direction, principal):
    packet = decode_canonical(_Packet,raw)
    body = bytes.fromhex(packet.body_hex)
    if packet.principal != principal or not hmac.compare_digest(packet.mac,_mac(secret,direction,nonce,principal,body)):
        raise ValueError('IPC authentication failed')
    return body


class CustodyIPCClient:
    """One authenticated exchange per connection; never retries automatically."""
    def __init__(self, address, *, principal, secret):
        if address[0] != '127.0.0.1' or type(secret) is not bytes or len(secret)!=32:
            raise ValueError('Explicit loopback fixture credentials required')
        self.address,self.principal,self.secret = address,principal,secret

    def exchange(self, request, *, timeout=5):
        if type(timeout) not in (int,float) or not 0 < timeout <= 5:
            raise ValueError('Bounded timeout required')
        deadline = monotonic()+timeout
        try:
            raw = canonical_bytes(request)
            decode_canonical(IPCRequest,raw)
            with socket.create_connection(self.address,timeout=timeout) as sock:
                hello = decode_canonical(_Hello,receive_frame(sock,deadline))
                send_frame(sock,_packet(self.principal,raw,self.secret,hello.nonce,b'REQUEST'),deadline)
                reply = receive_frame(sock,deadline)
                result = decode_canonical(IPCResult,_unpack(reply,self.secret,hello.nonce,b'RESPONSE',self.principal))
                _timeout(sock,deadline)
                return result
        except (OSError, ValueError):
            # Delivery does not prove whether server-side signing occurred.
            return IPCResult(status='OUTCOME_UNKNOWN')


class CustodyIPCBroker:
    """Sequential, bounded fixture broker; instantiate INSIDE the child process.

    Credentials and pins are host-supplied. No network API can change policy,
    choose trust records, or select fault modes. No pickle is read from sockets.
    """
    def __init__(self, provider, *, credentials, custody_inputs, authorization, epoch_clock,
                 mode='SUCCESS', hook=lambda point:None):
        if type(provider) is not TestCustodyProvider or not 1 <= len(credentials) <= 16:
            raise ValueError('Bounded fixture provider required')
        if any(type(k) is not str or type(v) is not bytes or len(v)!=32 for k,v in credentials.items()):
            raise ValueError('Fixture credentials required')
        self.provider,self.credentials = provider,dict(credentials)
        self.inputs,self.authorization,self.epoch = dict(custody_inputs),authorization,epoch_clock
        self.mode,self.hook = mode,hook
        self._secret,self._boot = secrets.token_bytes(32),secrets.token_hex(32)
        self._entries,self._attempts = {},set()

    def _authorized(self, principal, action):
        try:
            return self.authorization(principal,action) is True
        except Exception:
            return False

    def _issue(self, command, principal, connection_deadline):
        if not self._authorized(principal,'SIGN'):
            return IPCResult(status='ACCESS_DENIED')
        request = command.request
        if (command.token or type(request) is not CustodySignRequest
                or record_digest(request)!=command.request_digest or request.signer_id!=principal):
            return IPCResult(status='REQUEST_MISMATCH')
        if len(self._entries)>=MAX_TOKENS:
            return IPCResult(status='CAPACITY_EXCEEDED')
        if request.attempt_id in self._attempts:
            return IPCResult(status='OPERATION_CONFLICT')
        args={**self.inputs,'signer_id':principal}
        if evaluate_custody_request(request,now=self.epoch(),**args).status!='READY':
            return IPCResult(status='REQUEST_DENIED')
        if not self._authorized(principal,'SIGN'):
            return IPCResult(status='ACCESS_DENIED')
        if connection_deadline is not None and monotonic()>=connection_deadline:
            return IPCResult(status='DEADLINE_EXCEEDED')
        token_id=secrets.token_hex(32)
        digest=command.request_digest
        binding=(self._boot+token_id+digest+principal).encode()
        token=token_id+'.'+hmac.new(self._secret,binding,sha256).hexdigest()
        deadline=monotonic()+command.budget_ms/1000
        if connection_deadline is not None:deadline=min(deadline,connection_deadline)
        self._entries[token]=dict(principal=principal,digest=digest,request=request,
            deadline=deadline,used=False,result=None)
        self._attempts.add(request.attempt_id)
        return IPCResult(status='ISSUED',token=token)

    def _execute(self, command, principal, *, connection_deadline=None):
        if command.action=='ISSUE':return self._issue(command,principal,connection_deadline)
        # Authenticate and authorize before exposing token/operation existence.
        permission='RECOVER' if command.action=='RECOVER' else 'SIGN'
        if not self._authorized(principal,permission):
            # A recognized owner burns its own presented token on denial without
            # revealing whether it exists. Foreign credentials cannot burn it.
            denied_entry=self._entries.get(command.token)
            if (command.action=='SIGN' and denied_entry is not None
                    and denied_entry['principal']==principal and not denied_entry['used']):
                denied_entry['used']=True
                denied_entry['result']=IPCResult(status='ACCESS_DENIED')
            return IPCResult(status='ACCESS_DENIED')
        entry=self._entries.get(command.token)
        if entry is None or entry['principal']!=principal:
            return IPCResult(status='TOKEN_INVALID')
        if command.action=='RECOVER':
            if command.request is not None or command.request_digest!=entry['digest']:
                return IPCResult(status='REQUEST_MISMATCH')
            saved=entry['result']
            if saved is None:return IPCResult(status='NO_RECORDED_OUTCOME')
            return IPCResult(status='RECOVERED',outcome=saved.status,response=saved.response)
        if entry['used']:return IPCResult(status='TOKEN_ALREADY_CONSUMED')
        entry['used']=True
        deadline=entry['deadline'] if connection_deadline is None else min(entry['deadline'],connection_deadline)
        result=IPCResult(status='OUTCOME_UNKNOWN')
        try:
            if command.request is not None or command.request_digest!=entry['digest']:
                result=IPCResult(status='REQUEST_MISMATCH')
            elif monotonic()>=deadline:
                result=IPCResult(status='DEADLINE_EXCEEDED')
            else:
                self.hook('before_dispatch')
                if not self._authorized(principal,'SIGN'):
                    result=IPCResult(status='ACCESS_DENIED')
                elif monotonic()>=deadline:
                    result=IPCResult(status='DEADLINE_EXCEEDED')
                else:
                    handoff=self.provider.mint_handoff_for_testing(command.token[:64],entry['request'],deadline=deadline)
                    returned=self.provider.sign(handoff,**self.inputs,signer_id=principal,mode=self.mode)
                    self.hook('after_dispatch')
                    if not self._authorized(principal,'SIGN'):
                        result=IPCResult(status='ACCESS_DENIED')
                    elif monotonic()>=deadline:
                        result=IPCResult(status='RESULT_DISCARDED')
                    else:result=IPCResult(status=returned.status,response=returned.response)
        except Exception:
            result=IPCResult(status='OUTCOME_UNKNOWN')
        entry['result']=result
        self.hook('recorded')
        return result

    def serve_connection(self, sock):
        deadline=monotonic()+5
        try:
            nonce=secrets.token_hex(32)
            send_frame(sock,canonical_bytes(_Hello(nonce=nonce)),deadline)
            raw=receive_frame(sock,deadline)
            packet=decode_canonical(_Packet,raw)
            secret=self.credentials.get(packet.principal)
            if secret is None:return
            body=_unpack(raw,secret,nonce,b'REQUEST',packet.principal)
            command=decode_canonical(IPCRequest,body)
            _timeout(sock,deadline)
            result=self._execute(command,packet.principal,connection_deadline=deadline)
            if command.action=='RECOVER' and not self._authorized(packet.principal,'RECOVER'):
                result=IPCResult(status='ACCESS_DENIED')
            if command.action=='SIGN' and result.status=='VERIFIED':
                entry=self._entries[command.token]
                if not self._authorized(packet.principal,'SIGN') or monotonic()>=entry['deadline']:
                    result=IPCResult(status='RESULT_DISCARDED')
                    entry['result']=result
                else:deadline=min(deadline,entry['deadline'])
            send_frame(sock,_packet(packet.principal,canonical_bytes(result),secret,nonce,b'RESPONSE'),deadline)
        except (OSError,ValueError):
            return

    def serve(self, listener, stop):
        if listener.getsockname()[0]!='127.0.0.1':raise ValueError('Loopback only')
        listener.settimeout(.1)
        while not stop.is_set():
            try:sock,_=listener.accept()
            except socket.timeout:continue
            with sock:self.serve_connection(sock)

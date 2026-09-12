"""Test-only mTLS response delivery, retained public bytes, and local commit recovery."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event
from time import monotonic
import os
import socket
import ssl

import pytest
from test_signed_response_to_client_storage_integration import (
    pki, case, inventory, config, update, signed, host, stored, reconciliation,
    sim, db, writer, NOW, bridge_case, signing, harness, submit, prepare, sign,
    apply, state, dump, forbid_upstream, crash,
)
from test_mtls import server, client
from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.client_high_water_logic import AdvancementRequest, decode_client_record
from tnc.provenance.client_high_water_store import TestClientHighWaterStore, ClientStoreError
from tnc.provenance.reconciliation_verifier import SignedObservation, decode_v2_record
from tnc.provenance.observation_response_delivery import (
    encode_signed_response, send_signed_response, receive_signed_response, ResponseDeliveryError,
)
import tnc.provenance.observation_response_delivery as delivery
import tnc.provenance.mtls as mtls


def wire(h, *, mode='normal', read_timeout=5, read_deadline=None, send_deadline=None, client_context_mismatch=False):
    s=h.upstream; release=Event()
    host_server=server(s.pki,s.registry,clock=lambda:s.now)
    def serve(listener):
        raw,_=listener.accept()
        with host_server.accept(raw) as conn:
            response=sign(s,conn,prepare(s,conn))
            before=conn._socket.gettimeout()
            try:
                if mode=='drop':return response,None,before
                if mode=='silent':
                    assert release.wait(5)
                    return response,None,before
                framed=encode_signed_response(response)
                if mode=='short-header':conn.sendall(framed[:2])
                elif mode=='short-body':conn.sendall(framed[:-10])
                elif mode=='oversize':conn.sendall((32769).to_bytes(4,'big'))
                elif mode=='zero':conn.sendall(bytes(4))
                elif mode=='padding':
                    raw=b' '+canonical_bytes(response);conn.sendall(len(raw).to_bytes(4,'big')+raw)
                else:
                    if mode=='bad-signature':response=response.model_copy(update={'signature_hex':'0'*128})
                    if mode=='oversize-send':response=response.model_copy(update={'signature_hex':'0'*65536})
                    if mode=='revoked':s.registry.state=s.registry.state.model_copy(update={'credentials':(),'revision':2})
                    if mode=='wrong-principal':response=response.model_copy(update={'payload':response.payload.model_copy(update={'principal_id':'other'})})
                    send_signed_response(conn,response,deadline=send_deadline if send_deadline is not None else monotonic()+5)
                    assert conn._socket.gettimeout()==before
                return response,None,before
            except ResponseDeliveryError as error:
                return response,error,before
    with socket.socket() as listener,ThreadPoolExecutor(max_workers=1) as pool:
        listener.settimeout(5);listener.bind(('127.0.0.1',0));listener.listen(1)
        pending=pool.submit(serve,listener)
        received,error=None,None
        context=client(s.pki)
        with socket.create_connection(listener.getsockname(),timeout=5) as raw:
            with context.wrap_socket(raw,server_hostname='localhost') as conn:
                request=canonical_bytes(s.request)
                conn.sendall(len(request).to_bytes(4,'big')+request)
                before=conn.gettimeout()
                try:
                    received=receive_signed_response(conn,trusted_context=client(s.pki) if client_context_mismatch else context,
                        deadline=monotonic()+read_timeout if read_deadline is None else read_deadline)
                    assert conn.gettimeout()==before
                except ResponseDeliveryError as exc:error=exc
                finally:release.set()
        sent,server_error,_=pending.result(timeout=8)
    return received,error,sent,server_error


def retained(h,raw,operation='delivery-1'):
    s=h.upstream
    return AdvancementRequest(operation_id=operation,response=decode_v2_record(SignedObservation,raw),
        retained_request=s.request,trust_store=s.trust,trusted_checkpoint=s.checkpoint)


def retain_fixture(path,request):
    # Test-owned completed retention, not a production inbox or power-loss claim.
    with path.open('xb') as stream:
        stream.write(canonical_bytes(request));stream.flush();os.fsync(stream.fileno())


def test_roundtrip_bytes_then_client_commit(harness):
    h=harness;submit(h.writer,h.sim);before=dump(h.client.path)
    raw,error,sent,server_error=wire(h)
    assert error is None and server_error is None and raw==canonical_bytes(sent)
    assert dump(h.client.path)==before  # Complete delivery is not local commitment.
    result=apply(h,retained(h,raw))
    assert result.status=='VALID_ADVANCE' and state(h).authority_revision==2


def test_partial_writes_and_fragmented_reads(harness,monkeypatch):
    original_send=ssl.SSLSocket.send;original_recv=ssl.SSLSocket.recv;writes=[];reads=[]
    def send(sock,data,*a,**kw):
        if sock.server_side:
            writes.append(len(data));data=data[:1 if len(writes)<4 else 127]
        return original_send(sock,data,*a,**kw)
    def recv(sock,size,*a,**kw):
        if not sock.server_side:
            reads.append(size);size=min(size,1 if len(reads)<4 else 61)
        return original_recv(sock,size,*a,**kw)
    monkeypatch.setattr(ssl.SSLSocket,'send',send);monkeypatch.setattr(ssl.SSLSocket,'recv',recv)
    raw,error,sent,server_error=wire(harness)
    assert error is None and server_error is None and raw==canonical_bytes(sent)
    assert len(writes)>3 and len(reads)>3


@pytest.mark.parametrize('mode',['drop','short-header','short-body','oversize','zero','padding','oversize-send'])
def test_incomplete_or_invalid_delivery_never_commits(harness,mode):
    before=dump(harness.client.path)
    raw,error,_,_=wire(harness,mode=mode)
    assert raw is None and isinstance(error,ResponseDeliveryError)
    assert str(error)=='Delivery failed' and dump(harness.client.path)==before


def test_complete_frame_still_requires_signature_verification(harness):
    h=harness;raw,error,_,_=wire(h,mode='bad-signature');before=dump(h.client.path)
    assert error is None and raw is not None
    with pytest.raises(ClientStoreError,match='VERIFICATION_FAILED'):apply(h,retained(h,raw))
    assert dump(h.client.path)==before


def test_drop_before_delivery_requires_fresh_observation(harness,monkeypatch):
    h=harness;calls=[];original=h.upstream.signer.sign
    def signing(*a,**kw):calls.append(1);return original(*a,**kw)
    monkeypatch.setattr(h.upstream.signer,'sign',signing)
    raw,error,old,_=wire(h,mode='drop')
    assert raw is None and error is not None and state(h).local_sequence==0
    submit(h.writer,h.sim)
    h.upstream.request=h.upstream.request.model_copy(update={'challenge':'d'*64})
    raw,error,new,_=wire(h)
    assert error is None and old.payload.request_digest!=new.payload.request_digest and len(calls)==2
    assert old.payload.authority_revision==1 and new.payload.authority_revision==2
    assert apply(h,retained(h,raw,'fresh-cycle')).status=='VALID_ADVANCE'


@pytest.mark.parametrize('point,committed',[('before_commit',False),('after_commit',True)])
def test_retained_delivery_survives_client_crash(harness,tmp_path,monkeypatch,point,committed):
    h=harness;submit(h.writer,h.sim);raw,error,_,_=wire(h);assert error is None
    request=retained(h,raw);path=tmp_path/'retained_public_request.json';retain_fixture(path,request)
    h.upstream.signer.close();crash(h,request,point)
    assert state(h).local_sequence==int(committed)
    saved=canonical_bytes(state(h).history[0].receipt) if committed else None
    recovered=decode_client_record(AdvancementRequest,path.read_bytes())
    h.client=TestClientHighWaterStore(h.client.path,trusted_initial_anchor=h.anchor,clock=lambda:h.t+1000 if committed else h.t)
    forbid_upstream(h,monkeypatch)
    result=apply(h,recovered)
    assert result.status==('RECOVERED' if committed else 'VALID_ADVANCE')
    if committed:assert result.receipt_bytes==saved


def test_retained_uncommitted_expired_delivery_is_not_recovery(harness,tmp_path,monkeypatch):
    h=harness;raw,error,_,_=wire(h);assert error is None
    request=retained(h,raw);path=tmp_path/'uncommitted.json';retain_fixture(path,request)
    h.client.clock=lambda:request.response.payload.expiry;before=dump(h.client.path)
    forbid_upstream(h,monkeypatch)
    with pytest.raises(ClientStoreError,match='VERIFICATION_FAILED'):
        apply(h,decode_client_record(AdvancementRequest,path.read_bytes()))
    assert dump(h.client.path)==before


def test_lost_local_completion_ack_needs_no_network_ack(harness,monkeypatch):
    h=harness;raw,error,_,_=wire(h);assert error is None
    request=retained(h,raw)
    def hook(where):
        if where=='after_commit':raise RuntimeError('lost local completion acknowledgement')
    h.client._hook=hook
    with pytest.raises(ClientStoreError,match='OUTCOME_UNKNOWN'):apply(h,request)
    saved=canonical_bytes(state(h).history[0].receipt)
    h.client=TestClientHighWaterStore(h.client.path,trusted_initial_anchor=h.anchor,clock=lambda:h.t+1000)
    forbid_upstream(h,monkeypatch)
    assert apply(h,request).receipt_bytes==saved


def test_receive_total_deadline(harness):
    raw,error,_,_=wire(harness,mode='silent',read_timeout=0.05)
    assert raw is None and isinstance(error,ResponseDeliveryError)


def test_cumulative_partial_send_deadline(harness,monkeypatch):
    ticks=[0.0];sent=[];original=ssl.SSLSocket.send
    monkeypatch.setattr(mtls,'monotonic',lambda:ticks[0])
    monkeypatch.setattr(delivery,'monotonic',lambda:ticks[0])
    def send(sock,data,*a,**kw):
        if sock.server_side:
            count=original(sock,data[:1],*a,**kw);sent.append(count);ticks[0]+=2.0;return count
        return original(sock,data,*a,**kw)
    monkeypatch.setattr(ssl.SSLSocket,'send',send)
    raw,error,_,server_error=wire(harness,send_deadline=5.0)
    assert raw is None and isinstance(error,ResponseDeliveryError) and isinstance(server_error,ResponseDeliveryError)
    assert sent==[1,1,1]


@pytest.mark.parametrize('mode',['revoked','wrong-principal'])
def test_sender_identity_check(harness,mode):
    raw,error,_,server_error=wire(harness,mode=mode)
    assert raw is None and isinstance(error,ResponseDeliveryError) and isinstance(server_error,ResponseDeliveryError)


def test_receiver_requires_host_context(harness):
    raw,error,_,_=wire(harness,client_context_mismatch=True)
    assert raw is None and isinstance(error,ResponseDeliveryError)


@pytest.mark.parametrize('deadline',[0,float('nan'),True])
def test_invalid_deadlines_rejected_before_delivery(harness,deadline):
    raw,error,_,server_error=wire(harness,send_deadline=deadline)
    assert raw is None and isinstance(error,ResponseDeliveryError) and isinstance(server_error,ResponseDeliveryError)


def test_cumulative_fragmented_read_deadline(harness,monkeypatch):
    ticks=[0.0];reads=[];original=ssl.SSLSocket.recv
    monkeypatch.setattr(delivery,'monotonic',lambda:ticks[0])
    def recv(sock,size,*a,**kw):
        if not sock.server_side:
            data=original(sock,min(size,1),*a,**kw);reads.append(len(data));ticks[0]+=2.0;return data
        return original(sock,size,*a,**kw)
    monkeypatch.setattr(ssl.SSLSocket,'recv',recv)
    raw,error,_,_=wire(harness,read_deadline=5.0)
    assert raw is None and isinstance(error,ResponseDeliveryError) and reads==[1,1,1]


def test_identity_change_during_partial_write_stops_delivery(harness,monkeypatch):
    original=ssl.SSLSocket.send;writes=[];s=harness.upstream
    def send(sock,data,*a,**kw):
        if sock.server_side:
            sent=original(sock,data[:1],*a,**kw);writes.append(sent)
            current=s.registry.state
            changed=current.credentials[0].model_copy(update={'principal_id':'other'})
            s.registry.state=current.model_copy(update={'revision':2,'credentials':(changed,)})
            return sent
        return original(sock,data,*a,**kw)
    monkeypatch.setattr(ssl.SSLSocket,'send',send)
    raw,error,_,server_error=wire(harness)
    assert raw is None and isinstance(error,ResponseDeliveryError) and isinstance(server_error,ResponseDeliveryError)
    assert writes==[1]


def test_zero_progress_write_fails_closed(harness,monkeypatch):
    original=ssl.SSLSocket.send
    def send(sock,data,*a,**kw):return 0 if sock.server_side else original(sock,data,*a,**kw)
    monkeypatch.setattr(ssl.SSLSocket,'send',send)
    raw,error,_,server_error=wire(harness)
    assert raw is None and isinstance(error,ResponseDeliveryError) and isinstance(server_error,ResponseDeliveryError)

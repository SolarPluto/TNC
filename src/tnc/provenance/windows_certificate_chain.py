"""Private Windows CryptoAPI chain adapter; uses temporary memory stores only."""
import ctypes as c
from ctypes import wintypes as w
from contextlib import ExitStack
from datetime import datetime, timezone
import sys


class CertificateVerificationError(Exception):
    pass


class _Usage(c.Structure):
    _fields_ = [('count', w.DWORD), ('oids', c.POINTER(c.c_char_p))]


class _Match(c.Structure):
    _fields_ = [('kind', w.DWORD), ('usage', _Usage)]


class _Parameters(c.Structure):
    _fields_ = [('size', w.DWORD), ('usage', _Match), ('issuance', _Match),
        ('timeout', w.DWORD), ('freshness', w.BOOL), ('fresh_seconds', w.DWORD),
        ('resync', c.c_void_p), ('strong', c.c_void_p), ('strong_flags', w.DWORD)]


class _Engine(c.Structure):
    _fields_ = [('size', w.DWORD), ('restricted_root', w.HANDLE), ('restricted_trust', w.HANDLE),
        ('restricted_other', w.HANDLE), ('count', w.DWORD), ('stores', c.c_void_p),
        ('flags', w.DWORD), ('timeout', w.DWORD), ('cache', w.DWORD), ('cycles', w.DWORD),
        ('exclusive_root', w.HANDLE), ('exclusive_people', w.HANDLE), ('exclusive_flags', w.DWORD)]


class _Trust(c.Structure):
    _fields_ = [('errors', w.DWORD), ('info', w.DWORD)]


class _Cert(c.Structure):
    _fields_ = [('encoding', w.DWORD), ('data', c.c_void_p), ('length', w.DWORD),
                ('info', c.c_void_p), ('store', w.HANDLE)]


class _Element(c.Structure):
    _fields_ = [('size', w.DWORD), ('certificate', c.POINTER(_Cert)), ('trust', _Trust)]


class _SimpleChain(c.Structure):
    _fields_ = [('size', w.DWORD), ('trust', _Trust), ('count', w.DWORD),
                ('elements', c.POINTER(c.POINTER(_Element)))]


class _Chain(c.Structure):
    _fields_ = [('size', w.DWORD), ('trust', _Trust), ('count', w.DWORD),
                ('chains', c.POINTER(c.POINTER(_SimpleChain)))]


class _SSL(c.Structure):
    _fields_ = [('size', w.DWORD), ('auth_type', w.DWORD), ('checks', w.DWORD), ('name', w.LPWSTR)]


class _Policy(c.Structure):
    _fields_ = [('size', w.DWORD), ('flags', w.DWORD), ('extra', c.c_void_p)]


class _PolicyStatus(c.Structure):
    _fields_ = [('size', w.DWORD), ('error', w.DWORD), ('chain', w.LONG),
                ('element', w.LONG), ('extra', c.c_void_p)]


class _WindowsChainAPI:
    def __init__(self):
        if sys.platform != 'win32':
            raise CertificateVerificationError('Windows required')
        self.lib = c.WinDLL('crypt32.dll', use_last_error=True, winmode=0x800)
        def bind(name, args, result):
            fn = getattr(self.lib, name)
            fn.argtypes, fn.restype = args, result
        bind('CertOpenStore', [c.c_void_p,w.DWORD,w.HANDLE,w.DWORD,c.c_void_p], w.HANDLE)
        bind('CertCloseStore', [w.HANDLE,w.DWORD], w.BOOL)
        for name in ('CertAddEncodedCertificateToStore', 'CertAddEncodedCRLToStore'):
            bind(name, [w.HANDLE,w.DWORD,c.c_void_p,w.DWORD,w.DWORD,c.c_void_p], w.BOOL)
        bind('CertCreateCertificateContext', [w.DWORD,c.c_void_p,w.DWORD], c.POINTER(_Cert))
        bind('CertFreeCertificateContext', [c.POINTER(_Cert)], w.BOOL)
        bind('CertCreateCertificateChainEngine', [c.POINTER(_Engine),c.POINTER(w.HANDLE)], w.BOOL)
        bind('CertFreeCertificateChainEngine', [w.HANDLE], None)
        bind('CertGetCertificateChain', [w.HANDLE,c.POINTER(_Cert),c.POINTER(w.FILETIME),w.HANDLE,
            c.POINTER(_Parameters),w.DWORD,c.c_void_p,c.POINTER(c.POINTER(_Chain))], w.BOOL)
        bind('CertFreeCertificateChain', [c.POINTER(_Chain)], None)
        bind('CertVerifyCertificateChainPolicy', [c.c_void_p,c.POINTER(_Chain),c.POINTER(_Policy),
            c.POINTER(_PolicyStatus)], w.BOOL)

    def verify(self, leaf, roots, intermediates, crls, now):
        with ExitStack() as stack:
            def store():
                handle = self.lib.CertOpenStore(2, 0, None, 0x2000, None)
                if not handle:
                    raise CertificateVerificationError('Memory store unavailable')
                def close():
                    if not self.lib.CertCloseStore(handle, 0):
                        raise CertificateVerificationError('Store cleanup failed')
                stack.callback(close)
                return handle
            root_store, other = store(), store()
            def add(handle, values, crl=False):
                fn = self.lib.CertAddEncodedCRLToStore if crl else self.lib.CertAddEncodedCertificateToStore
                for data in values:
                    if not fn(handle, 1, data, len(data), 4, None):
                        raise CertificateVerificationError('Store insertion failed')
            add(root_store, roots)
            add(other, (*roots, *intermediates))
            add(other, crls, True)
            engine = w.HANDLE()
            config = _Engine()
            config.size, config.exclusive_root = c.sizeof(config), root_store
            # Exclusive-root mode rejects restricted-store combinations on Windows.
            # Supply intermediates/CRLs via the per-call store and require exact
            # supplied chain bytes plus independent CRL checks in the outer gate.
            config.flags, config.cache = 0x2004, 32
            if not self.lib.CertCreateCertificateChainEngine(c.byref(config), c.byref(engine)):
                raise CertificateVerificationError('Chain engine unavailable')
            stack.callback(self.lib.CertFreeCertificateChainEngine, engine)
            cert = self.lib.CertCreateCertificateContext(1, leaf, len(leaf))
            if not cert:
                raise CertificateVerificationError('Certificate context unavailable')
            def free_certificate():
                if not self.lib.CertFreeCertificateContext(cert):
                    raise CertificateVerificationError('Certificate cleanup failed')
            stack.callback(free_certificate)
            delta = now.astimezone(timezone.utc) - datetime(1601,1,1,tzinfo=timezone.utc)
            ticks = (delta.days*86400+delta.seconds)*10000000+delta.microseconds*10
            at = w.FILETIME(ticks & 0xffffffff, ticks >> 32)
            oids = (c.c_char_p*1)(b'1.3.6.1.5.5.7.3.2')
            params = _Parameters()
            params.size, params.usage = c.sizeof(params), _Match(0, _Usage(1, oids))
            result = c.POINTER(_Chain)()
            # Chain cache-only + disable AIA + revocation cache-only + chain excluding root.
            flags = 0xc0002004
            if not self.lib.CertGetCertificateChain(engine, cert, c.byref(at), other,
                    c.byref(params), flags, None, c.byref(result)):
                raise CertificateVerificationError('Chain unavailable')
            stack.callback(self.lib.CertFreeCertificateChain, result)
            if not result or result.contents.trust.errors or result.contents.count != 1:
                raise CertificateVerificationError('Chain rejected')
            ssl = _SSL(c.sizeof(_SSL), 1, 0, None)  # AUTH_TYPE_CLIENT, no ignored checks.
            policy = _Policy(c.sizeof(_Policy), 0, c.cast(c.pointer(ssl), c.c_void_p))
            status = _PolicyStatus()
            status.size = c.sizeof(status)
            if not self.lib.CertVerifyCertificateChainPolicy(4, result, c.byref(policy), c.byref(status)) or status.error:
                raise CertificateVerificationError('Client policy rejected')
            simple = result.contents.chains[0].contents
            if simple.trust.errors or not 2 <= simple.count <= 32:
                raise CertificateVerificationError('Invalid chain extent')
            encoded = []
            for i in range(simple.count):
                element = simple.elements[i].contents
                certificate = element.certificate.contents
                if element.trust.errors or not 0 < certificate.length <= 4*1024*1024:
                    raise CertificateVerificationError('Invalid chain element')
                encoded.append(c.string_at(certificate.data, certificate.length))
            return tuple(encoded)

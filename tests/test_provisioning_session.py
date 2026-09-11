"""Session assembly and writer transactions; native integration uses temporary data."""
from contextlib import contextmanager
from datetime import timedelta
import os
import sqlite3
import threading
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from test_provisioning_validation import case, SID, ROOT, NOW
from test_protected_provisioning import FakeAPI, open_native_path
from test_authorization_writer import snapshot as db_snapshot
from tnc.provenance.authorization_models import record_digest, canonical_bytes
from tnc.provenance.authorization_writer import AdministrationWriter, ProvisioningAuthorization
from tnc.provenance.host_auth import AuthorizationError
from tnc.provenance.protected_provisioning import _load
from tnc.provenance.provisioning_models import CertificateValidationEvidence
from tnc.provenance.provisioning_session import WindowsProvisioningSession
from tnc.provenance.sqlite_review_store import SqliteReviewStore
from tnc.provenance.windows_identity import WindowsOperatorIdentity
import tnc.provenance.provisioning_session as module
from test_mtls import pki


class Clock:
    utc = NOW
    mono = 100.


@pytest.fixture
def setup(case, tmp_path, monkeypatch):
    clock, calls, snapshots = Clock(), [], []
    path = tmp_path/'activation.sqlite'
    case['descriptor'] = case['descriptor'].model_copy(update={'database_path':str(path)})
    identity = WindowsOperatorIdentity(user_sid=SID, process_id=os.getpid(),
        thread_id=threading.get_native_id(), elevated=False)
    def reader():
        calls.append('identity')
        return identity
    def loader(descriptor):
        calls.append('load')
        result = _load(descriptor, FakeAPI(case))
        snapshots.append(result)
        return result
    def certificate(snapshot, *, now):
        calls.append('certificate')
        return CertificateValidationEvidence(leaf_fingerprint=ROOT,chain_fingerprints=(ROOT,'b'*64),
            root_fingerprint='b'*64,crl_digests=('c'*64,),validated_at=now,
            valid_from=now-timedelta(seconds=1),valid_until=now+timedelta(hours=1),
            snapshot_hash=record_digest(snapshot.record),profile_hash=record_digest(snapshot.policy.certificate_profile))
    monkeypatch.setattr(module,'_utcnow',lambda:clock.utc)
    monkeypatch.setattr(module,'_monotonic',lambda:clock.mono)
    monkeypatch.setattr(module,'read_windows_operator_identity',reader)
    monkeypatch.setattr(module,'load_protected_provisioning',loader)
    monkeypatch.setattr(module,'validate_nominated_certificate',certificate)
    store=SqliteReviewStore.provision(path=path,allowed_reviewers=frozenset())
    store.migrate_to_v2()
    store.migrate_to_v3()
    store=SqliteReviewStore.open_existing(path=path,allowed_reviewers=frozenset(),
        bootstrap_anchor=case['descriptor'].bootstrap_anchor)
    writer=AdministrationWriter(store=store,clock=lambda:clock.utc)
    return case,clock,calls,snapshots,identity,writer


def test_assembly_order_and_no_io_commit(setup):
    case,clock,calls,snapshots,identity,writer=setup
    with WindowsProvisioningSession(case['descriptor']) as session:
        proof=session.verify_activation(case['manifest'])
        assert calls==['identity','load','certificate','identity']
        assert proof.operator_id==SID and proof.valid_until==NOW+timedelta(seconds=60)
        session.verify_commit(proof,database_path=str(writer._store._path))
        assert len(calls)==4
    assert not snapshots[0]._handles


def test_writer_activation_and_exact_retry(setup):
    case,clock,_,snapshots,_,writer=setup
    with WindowsProvisioningSession(case['descriptor']) as session:
        receipt=writer.migrate_to_v4(provisioning=session,manifest=case['manifest'])
        before=db_snapshot(writer)
        clock.utc+=timedelta(seconds=1)
        clock.mono+=1
        assert writer.migrate_to_v4(provisioning=session,manifest=case['manifest'])==receipt
        assert db_snapshot(writer)==before
        assert len(writer.history())==2
        assert not snapshots[0]._handles
    assert all(not s._handles for s in snapshots)


@pytest.mark.parametrize('kind',['monotonic','utc','rollback','mono_rollback','nan','wrong_database','wrong_proof'])
def test_live_commit_rejections(setup,kind):
    case,clock,_,_,_,writer=setup
    with WindowsProvisioningSession(case['descriptor']) as session:
        proof=session.verify_activation(case['manifest'])
        path=str(writer._store._path)
        if kind=='monotonic':clock.mono+=60
        if kind=='utc':clock.utc+=timedelta(seconds=60)
        if kind=='rollback':clock.utc-=timedelta(seconds=1)
        if kind=='mono_rollback':clock.mono-=1
        if kind=='nan':clock.mono=float('nan')
        if kind=='wrong_database':path+='other'
        if kind=='wrong_proof':proof=proof.model_copy(update={'deployment_id':'other'})
        with pytest.raises(AuthorizationError):session.verify_commit(proof,database_path=path)
        assert session._proof is None


@pytest.mark.parametrize('stage',['identity','load','certificate','second_identity'])
def test_verification_failure_cleanup(setup,monkeypatch,stage):
    case,_,_,snapshots,_,_=setup
    def fail(*args,**kwargs):raise OSError('private details')
    if stage in ('identity','second_identity'):
        reader=module.read_windows_operator_identity
        count=0
        def wrapped():
            nonlocal count
            count+=1
            if stage=='identity' or count==2:return fail()
            return reader()
        monkeypatch.setattr(module,'read_windows_operator_identity',wrapped)
    elif stage=='load':monkeypatch.setattr(module,'load_protected_provisioning',fail)
    else:monkeypatch.setattr(module,'validate_nominated_certificate',fail)
    with WindowsProvisioningSession(case['descriptor']) as session:
        with pytest.raises(AuthorizationError,match='^Access denied$'):session.verify_activation(case['manifest'])
        assert session._proof is None
    assert all(not s._handles for s in snapshots)


@pytest.mark.parametrize('field,value',[('user_sid','S-1-5-7'),('elevated',True),('process_id',1),('thread_id',1)])
def test_identity_change_rejected(setup,monkeypatch,field,value):
    case,_,_,snapshots,identity,_=setup
    reads=iter((identity,identity.model_copy(update={field:value})))
    monkeypatch.setattr(module,'read_windows_operator_identity',lambda:next(reads))
    with WindowsProvisioningSession(case['descriptor']) as session:
        with pytest.raises(AuthorizationError):session.verify_activation(case['manifest'])
    assert all(not s._handles for s in snapshots)


def test_manifest_mismatch_before_certificate(setup):
    case,_,calls,snapshots,_,_=setup
    with WindowsProvisioningSession(case['descriptor']) as session:
        with pytest.raises(AuthorizationError):session.verify_activation(case['manifest'].model_copy(update={'request_id':'other'}))
    assert 'certificate' not in calls and not snapshots[0]._handles


def test_expiry_during_verification(setup,monkeypatch):
    case,clock,_,snapshots,_,_=setup
    validate=module.validate_nominated_certificate
    def slow(*args,**kwargs):
        result=validate(*args,**kwargs)
        clock.mono+=60
        return result
    monkeypatch.setattr(module,'validate_nominated_certificate',slow)
    with WindowsProvisioningSession(case['descriptor']) as session:
        with pytest.raises(AuthorizationError):session.verify_activation(case['manifest'])
    assert not snapshots[0]._handles


def test_expiry_while_waiting_for_transaction(setup,monkeypatch):
    case,clock,_,_,_,writer=setup
    before=db_snapshot(writer)
    original=writer._store._transaction
    @contextmanager
    def delayed(**kwargs):
        with original(**kwargs) as opened:
            if kwargs.get('write'):clock.mono+=60
            yield opened
    monkeypatch.setattr(writer._store,'_transaction',delayed)
    with WindowsProvisioningSession(case['descriptor']) as session:
        with pytest.raises(AuthorizationError):writer.migrate_to_v4(provisioning=session,manifest=case['manifest'])
    assert db_snapshot(writer)==before


def test_expiry_after_ddl_rolls_back(setup,monkeypatch):
    import tnc.provenance.authorization_writer as writer_module
    case,clock,_,_,_,writer=setup
    before=db_snapshot(writer)
    original=writer_module._apply_v4
    def late(connection):
        original(connection)
        clock.mono+=60
    monkeypatch.setattr(writer_module,'_apply_v4',late)
    with WindowsProvisioningSession(case['descriptor']) as session:
        with pytest.raises(AuthorizationError):writer.migrate_to_v4(provisioning=session,manifest=case['manifest'])
    assert db_snapshot(writer)==before


def test_missing_live_commit_contract_fails_closed(setup):
    case,_,_,_,_,writer=setup
    before=db_snapshot(writer)
    class Legacy:
        def verify_activation(self,manifest):
            return ProvisioningAuthorization(operator_id=SID,session_id='provisioning-session',
                manifest_hash=record_digest(manifest),deployment_id=manifest.deployment_id,
                valid_from=NOW,valid_until=NOW+timedelta(seconds=60))
    with pytest.raises(AuthorizationError):writer.migrate_to_v4(provisioning=Legacy(),manifest=case['manifest'])
    assert db_snapshot(writer)==before


def test_session_cannot_cross_threads_or_reopen_after_close(setup):
    case,_,_,_,_,_=setup
    session=WindowsProvisioningSession(case['descriptor'])
    with ThreadPoolExecutor(max_workers=1) as pool:
        with pytest.raises(AuthorizationError):pool.submit(session.verify_activation,case['manifest']).result(timeout=5)
    session.close()
    session.close()
    with pytest.raises(AuthorizationError):session.verify_activation(case['manifest'])


def test_failed_refresh_invalidates_previous_proof(setup,monkeypatch):
    case,_,_,snapshots,_,writer=setup
    with WindowsProvisioningSession(case['descriptor']) as session:
        proof=session.verify_activation(case['manifest'])
        def fail():raise OSError('token unavailable')
        monkeypatch.setattr(module,'read_windows_operator_identity',fail)
        with pytest.raises(AuthorizationError):session.verify_activation(case['manifest'])
        with pytest.raises(AuthorizationError):session.verify_commit(proof,database_path=str(writer._store._path))
    assert not snapshots[0]._handles


def test_short_certificate_deadline_is_preserved(setup,monkeypatch):
    case,clock,_,_,_,writer=setup
    original=module.validate_nominated_certificate
    def short(*args,**kwargs):
        return original(*args,**kwargs).model_copy(update={'valid_until':NOW+timedelta(seconds=2)})
    monkeypatch.setattr(module,'validate_nominated_certificate',short)
    with WindowsProvisioningSession(case['descriptor']) as session:
        proof=session.verify_activation(case['manifest'])
        assert proof.valid_until==NOW+timedelta(seconds=2)
        clock.mono+=2
        with pytest.raises(AuthorizationError):session.verify_commit(proof,database_path=str(writer._store._path))


def test_proof_from_closed_session_is_not_portable(setup):
    case,_,_,_,_,writer=setup
    with WindowsProvisioningSession(case['descriptor']) as first:
        proof=first.verify_activation(case['manifest'])
    with WindowsProvisioningSession(case['descriptor']) as fresh:
        with pytest.raises(AuthorizationError):fresh.verify_commit(proof,database_path=str(writer._store._path))


def test_policy_permissions_are_rechecked_on_refresh(setup,monkeypatch):
    case,_,_,_,_,writer=setup
    original=module.load_protected_provisioning
    with WindowsProvisioningSession(case['descriptor']) as session:
        proof=session.verify_activation(case['manifest'])
        def denied(descriptor):
            api=FakeAPI(case)
            from test_protected_provisioning import sd
            api.bad=('config',{'security':sd(owner='S-1-5-7')})
            return _load(descriptor,api)
        monkeypatch.setattr(module,'load_protected_provisioning',denied)
        with pytest.raises(AuthorizationError):session.verify_activation(case['manifest'])
        with pytest.raises(AuthorizationError):session.verify_commit(proof,database_path=str(writer._store._path))


@pytest.fixture
def native_pending(case,pki):
    from test_provisioning_certificates import snapshot as certificate_snapshot
    from tnc.provenance.windows_identity import read_windows_operator_identity
    from tnc.provenance.windows_protected_files import _WindowsFileAPI,parse_security
    identity=read_windows_operator_identity()
    directory=pki.path/'configuration'
    directory.mkdir()
    path=pki.path/'native-activation.sqlite'
    with certificate_snapshot(case,pki) as initial:
        data=dict(initial.artifacts)
        policy=initial.policy.model_copy(update={'operator_sids':(identity.user_sid,),
            'valid_from':pki.now-timedelta(minutes=1),'valid_until':pki.now+timedelta(hours=1)})
        enrollment=initial.manifest.initial_enrollment
        enrollment=enrollment.model_copy(update={'credential':enrollment.credential.model_copy(update={
            'valid_from':pki.client[0].not_valid_before_utc,'valid_until':pki.client[0].not_valid_after_utc})})
        grant=initial.manifest.initial_grant
        grant=grant.model_copy(update={'permission':grant.permission.model_copy(update={
            'valid_from':policy.valid_from,'valid_until':policy.valid_until})})
        manifest=initial.manifest.model_copy(update={'valid_from':policy.valid_from,'valid_until':policy.valid_until,
            'initial_enrollment':enrollment,'initial_grant':grant,'admin_policy_hash':record_digest(policy)})
        anchor=initial.descriptor.bootstrap_anchor.model_copy(update={'operator_id':identity.user_sid,
            'manifest_hash':record_digest(manifest),'valid_from':policy.valid_from,'valid_until':policy.valid_until})
        descriptor=initial.descriptor.model_copy(update={'configuration_root':str(directory),'database_path':str(path),
            'policy_hash':record_digest(policy),'bootstrap_anchor':anchor})
    (directory/'policy.json').write_bytes(canonical_bytes(policy))
    (directory/'manifest.json').write_bytes(canonical_bytes(manifest))
    for name,body in data.items():(directory/name).write_bytes(body)
    # Synthetic host trust setup only: do not copy this allowlist discovery into deployment.
    api=_WindowsFileAPI()
    handles=open_native_path(api,directory)
    owners,writers=set(),set()
    parent=handles[-1]
    try:
        for name in ('policy.json','manifest.json',*data):handles.append(api.open_child(parent,name,False))
        for handle in handles:
            owner,entries=parse_security(api.facts(handle).security)
            owners.add(owner)
            writers.update(e[3] for e in entries)
    finally:
        for handle in reversed(handles):api.close(handle)
    descriptor=descriptor.model_copy(update={'trusted_owner_sids':tuple(sorted(owners)),
        'trusted_writer_sids':tuple(sorted(writers))})
    store=SqliteReviewStore.provision(path=path,allowed_reviewers=frozenset())
    store.migrate_to_v2()
    store.migrate_to_v3()
    store=SqliteReviewStore.open_existing(path=path,allowed_reviewers=frozenset(),bootstrap_anchor=anchor)
    return descriptor,manifest,AdministrationWriter(store=store),directory


@pytest.mark.skipif(sys.platform!='win32',reason='Real Windows session assembly')
def test_native_session_through_writer_and_retry(native_pending):
    descriptor,manifest,writer,directory=native_pending
    with WindowsProvisioningSession(descriptor) as session:
        receipt=writer.migrate_to_v4(provisioning=session,manifest=manifest)
        assert receipt.operator_id==descriptor.bootstrap_anchor.operator_id
        assert len(writer.history())==2
        with pytest.raises(OSError):(directory/'policy.json').write_bytes(b'replace')
        before=db_snapshot(writer)
        assert writer.migrate_to_v4(provisioning=session,manifest=manifest)==receipt
        assert db_snapshot(writer)==before
    assert (directory/'policy.json').read_bytes()


@pytest.mark.skipif(sys.platform!='win32',reason='Real Windows denial')
def test_native_bad_certificate_cannot_activate(native_pending):
    descriptor,manifest,writer,directory=native_pending
    before=db_snapshot(writer)
    (directory/'leaf.der').write_bytes(b'bad certificate')
    with WindowsProvisioningSession(descriptor) as session:
        with pytest.raises(AuthorizationError):writer.migrate_to_v4(provisioning=session,manifest=manifest)
    assert db_snapshot(writer)==before


def test_other_thread_transaction_delay_fences_lease(setup,monkeypatch):
    case,clock,_,_,identity,writer=setup
    before=db_snapshot(writer)
    ready=threading.Event()
    proceed=threading.Event()
    def current_identity():
        return identity.model_copy(update={'thread_id':threading.get_native_id()})
    monkeypatch.setattr(module,'read_windows_operator_identity',current_identity)
    original=writer._store._transaction
    @contextmanager
    def entering(**kwargs):
        if kwargs.get('write'):
            ready.set()
            assert proceed.wait(5)
        with original(**kwargs) as result:yield result
    monkeypatch.setattr(writer._store,'_transaction',entering)
    def worker():
        with WindowsProvisioningSession(case['descriptor']) as session:
            return writer.migrate_to_v4(provisioning=session,manifest=case['manifest'])
    with sqlite3.connect(writer._store._path,isolation_level=None) as blocker,ThreadPoolExecutor(max_workers=1) as pool:
        blocker.execute('BEGIN IMMEDIATE')
        pending=pool.submit(worker)
        try:
            assert ready.wait(5)
            clock.mono+=60
        finally:
            blocker.execute('ROLLBACK')
            proceed.set()
        with pytest.raises(AuthorizationError):pending.result(timeout=5)
    assert db_snapshot(writer)==before

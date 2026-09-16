"""Disposable native token capture; signing and policy admission remain disconnected.

Allowed clients use the existing operator account. Anonymous access is denied by
the unchanged DACL. Cleanup failures are injected after real impersonation, not
induced by corrupting OS handles or changing privileges.
"""
import ctypes as c
import os
import sys
import traceback
import uuid

import pytest

import test_windows_pipe_process as pipe
from tnc.provenance import windows_pipe_native as n
from tnc.provenance import windows_pipe_token as t
from tnc.provenance.windows_identity import read_windows_operator_identity

pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Native Windows token processes')


def _server(control, name, scenario, challenge):
    try:
        identity = read_windows_operator_identity()
        api = n.NativePipeApi()
        checks = pipe._NativeChecks(api)
        token_api = t.NativePipeTokenAPI()
        baseline = checks.handles()
        endpoint = n.OwnedPipeEndpoint(policy=pipe._policy(name, identity, checks), api=api)
        assert n.parse_security(checks.descriptor(endpoint._handle)) == n.parse_security(n._descriptor(endpoint._policy))
        pipe._send(control, kind='ready', name=name, pid=os.getpid(), birth=checks.birth(os.getpid()))
        assert pipe._receive(control)['kind'] == 'connect'
        connect = endpoint.begin_connect(pipe._plan('CONNECT', 1))
        pipe._send(control, kind='connecting')
        assert connect.wait_until(connect._plan.request_deadline)
        connect.dispose()
        read = endpoint.begin_read(pipe._plan('READ', 2, t.PREAMBLE_SIZE))
        assert read.wait_until(read._plan.request_deadline)
        counts = [baseline, checks.handles()]
        inspector = t.PipeTokenInspector(token_api)
        counts.append(checks.handles())
        calls, queries = [], []
        native_open = token_api.security.OpenThreadToken
        def open_token(thread, rights, as_self, returned):
            calls.append((rights, bool(as_self)))
            return native_open(thread, rights, as_self, returned)
        token_api.security.OpenThreadToken = open_token
        native_query = token_api._query
        def query(*args):
            result = native_query(*args)
            queries.append((args[1], result))
            return result
        token_api._query = query
        if scenario == 'bad_preamble':
            try:
                inspector.capture_preamble(endpoint, read, expected_challenge=challenge)
            except t.TokenCaptureError:
                result = {'status': 'INDETERMINATE', 'reason': 'PREAMBLE_REJECTED'}
            else:
                raise AssertionError('Wrong preamble accepted')
            assert not calls
        else:
            boundary = inspector.capture_preamble(endpoint, read, expected_challenge=challenge)
            if scenario == 'deadline':
                inspector._clock = lambda: read._plan.request_deadline
            elif scenario == 'query_failure':
                def unavailable(*args):
                    raise t.TokenCaptureError('INJECTED_QUERY_FAILURE')
                token_api.capture = unavailable
            elif scenario == 'revert_failure':
                token_api.revert = lambda: False
            elif scenario == 'close_failure':
                token_api.close = lambda token: False
            elif scenario == 'preexisting':
                assert token_api.impersonate(endpoint._handle)
            result = inspector.inspect(boundary).model_dump(mode='json')
            # Successful and rejected boundaries alike must be consumed.
            before_retry = len(calls)
            assert inspector.inspect(boundary).reason == 'BOUNDARY_UNAVAILABLE'
            assert len(calls) == before_retry
        counts.append(checks.handles())
        assert token_api.open_thread_token() is None
        assert read_windows_operator_identity().user_sid == identity.user_sid
        assert calls and all(rights == t.TOKEN_QUERY and as_self for rights, as_self in calls)
        read.dispose()
        endpoint.close()
        assert not n._OWNERS
        del inspector  # Release the inspector-owned Python lock handle.
        pipe._send(control, kind='done', result=result, query_calls=queries,
                   counts=counts, delta=checks.handles()-baseline, sid=identity.user_sid, reverted=True)
    except BaseException as error:
        try:
            pipe._send(control, kind='error', detail=type(error).__name__+':'+str(error)[:600],
                       line=traceback.extract_tb(error.__traceback__)[-1].lineno)
        finally:
            os._exit(74)
    finally:
        control.close()


def _client(control, info, scenario, challenge):
    try:
        api = n.NativePipeApi()
        checks = pipe._NativeChecks(api)
        level = 0 if scenario == 'anonymous_sqos' else 2 if scenario == 'impersonation' else 1
        handle = checks.kernel.CreateFileW(info['name'], n.CLIENT_RIGHTS, 0, None, 3,
            0x40000000 | 0x00100000 | (level << 16), None)
        assert n._valid_handle(handle), ('open', c.get_last_error())
        assert checks.peer(handle, True) == (info['pid'], info['birth'])
        io = pipe._ClientIO(api, handle)
        payload = t.PREAMBLE_PREFIX + (b'x'*32 if scenario == 'bad_preamble' else challenge)
        assert io.transfer('WRITE', payload) == len(payload)
        pipe._send(control, kind='sent')
        assert pipe._receive(control)['kind'] == 'close'
        assert api.close(handle)
        assert not io.allocations
        pipe._send(control, kind='closed')
    except BaseException as error:
        try:
            pipe._send(control, kind='error', detail=type(error).__name__+':'+str(error)[:600],
                       line=traceback.extract_tb(error.__traceback__)[-1].lineno)
        finally:
            os._exit(75)
    finally:
        control.close()


@pytest.fixture
def harness():
    value = pipe._Harness()
    yield value
    value.stop()


def _start(harness, scenario):
    name = r'\\.\pipe\TNC-' + uuid.uuid4().hex
    challenge = os.urandom(32)
    server, control = harness.spawn(_server, name, scenario, challenge)
    info = pipe._receive(control)
    assert info['kind'] == 'ready' and info['pid'] == server.pid
    pipe._send(control, kind='connect')
    assert pipe._receive(control)['kind'] == 'connecting'
    client, channel = harness.spawn(_client, info, scenario, challenge)
    assert pipe._receive(channel)['kind'] == 'sent'
    return server, control, client, channel, info


def _finish_client(harness, client, channel):
    pipe._send(channel, kind='close')
    assert pipe._receive(channel)['kind'] == 'closed'
    harness.join(client)


@pytest.mark.parametrize('scenario', ['identification', 'impersonation'])
def test_native_token_capture_and_reversion(harness, scenario):
    server, control, client, channel, _ = _start(harness, scenario)
    done = pipe._receive(control)
    # Known intermittent: one impersonation run reported delta=1 and passed on reruns.
    # Keep this invariant strict; rerun a recurrence until the leaked/transient handle
    # mechanism is identified rather than weakening the assertion without evidence.
    assert done['kind'] == 'done' and done['delta'] == 0 and done['reverted'], done
    result = done['result']
    assert result['status'] == 'CAPTURED', done
    assert result['source'] == 'NATIVE_TOKEN_API' and not result['authorization_granted']
    facts = result['facts']
    assert facts['user_sid'] == done['sid']
    assert facts['level'] == scenario.upper()
    assert facts['logon_sid'].startswith('S-1-5-5-')
    assert facts['authentication_id'] > 0 and facts['token_id'] > 0
    assert not facts['app_container_exclusion_proven']
    assert any(kind == t.STATISTICS for kind, _ in done['query_calls'])
    harness.join(server)
    _finish_client(harness, client, channel)


@pytest.mark.parametrize('scenario', ['bad_preamble', 'deadline', 'query_failure', 'anonymous_sqos'])
def test_native_capture_denials_revert_without_evidence(harness, scenario):
    server, control, client, channel, _ = _start(harness, scenario)
    done = pipe._receive(control)
    assert done['kind'] == 'done' and done['delta'] == 0 and done['reverted'], done
    assert done['result']['status'] == 'INDETERMINATE'
    assert not done['result'].get('facts')
    harness.join(server)
    _finish_client(harness, client, channel)


@pytest.mark.parametrize('scenario', ['revert_failure', 'close_failure', 'preexisting'])
def test_native_impersonation_fault_terminates_worker(harness, scenario):
    server, control, client, channel, info = _start(harness, scenario)
    server.join(10)
    assert not server.is_alive() and server.exitcode == 78
    # No successful audit result escaped the fatal worker.
    with pytest.raises((EOFError, BrokenPipeError)):
        if control.poll(2):
            control.recv_bytes(4096)
        else:
            pytest.fail('Terminated worker channel remained open')
    _finish_client(harness, client, channel)
    replacement, replacement_control, _ = pipe._start(harness, 'idle', name=info['name'])
    pipe._send(replacement_control, kind='close')
    assert pipe._receive(replacement_control) == {'kind': 'closed', 'delta': 0}
    harness.join(replacement)


def test_anonymous_identity_is_denied_by_unchanged_native_dacl(harness):
    server, control, info = pipe._start(harness, 'idle')
    client, channel = harness.spawn(pipe._client, info, 'anonymous')
    assert pipe._receive(channel) == {'kind': 'denied', 'error': 5, 'reverted': True}
    harness.join(client)
    pipe._send(control, kind='close')
    assert pipe._receive(control) == {'kind': 'closed', 'delta': 0}
    harness.join(server)

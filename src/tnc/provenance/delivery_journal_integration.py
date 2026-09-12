"""Test-only explicit delivery/journal steps. No dispatch loop or automatic re-signing."""
from tnc.provenance.authorization_models import canonical_bytes
from tnc.provenance.client_request_journal_store import TestClientRequestJournalStore, ClientJournalStoreResult
from tnc.provenance.observation_response_delivery import receive_signed_response


class DeliveryJournalIntegrationError(ValueError): pass


class TestDeliveryJournalIntegration:
    """Host-owned scaffold, not a production client or authorization boundary.

    Each method is a separate step. In particular apply_retained never records
    the acknowledgement of a newly applied high-water receipt in the journal.
    """
    __test__ = False

    def __init__(self, journal):
        if type(journal) is not TestClientRequestJournalStore:
            raise DeliveryJournalIntegrationError('Invalid journal')
        self.journal = journal

    def register_intent(self, intent, *, caller_principal):
        return self.journal.register_intent(intent, caller_principal=caller_principal)

    def _awaiting(self, operation_id, principal):
        # Store access checks principal before lookup. The read is not a reusable
        # grant; retention still revalidates the locked journal state afterwards.
        now=self.journal.clock()
        image=self.journal.load(caller_principal=principal, now=now)
        entry=next((e for e in image.entries if e.intent.operation_id==operation_id),None)
        if entry is None: raise DeliveryJournalIntegrationError('Access denied')
        if entry.state!='AWAITING_RESPONSE':
            raise DeliveryJournalIntegrationError('Use local recovery')
        if now>=entry.intent.expires_at: raise DeliveryJournalIntegrationError('Intent expired')
        return entry

    def request_frame(self, operation_id, *, caller_principal):
        """Frame the exact registered request; does not send or mark it dispatched."""
        entry=self._awaiting(operation_id,caller_principal)
        raw=canonical_bytes(entry.intent.request)
        if not 0<len(raw)<=16384: raise DeliveryJournalIntegrationError('Invalid request bound')
        return len(raw).to_bytes(4,'big')+raw

    def receive_and_retain(self, operation_id, connection, *, trusted_context, deadline, caller_principal):
        """Receive a bounded frame, then retain through the journal's locked verifier.

        A crash between receive and retention can still lose bytes. No fallback
        file, cache, or automatic fresh observation is created here.
        """
        self._awaiting(operation_id,caller_principal)
        raw=receive_signed_response(connection,trusted_context=trusted_context,deadline=deadline)
        return self.journal.retain_response(operation_id,raw,caller_principal=caller_principal)

    def recover(self, operation_id, *, caller_principal):
        """Read/reconcile local evidence only; never contact upstream."""
        return self.journal.recover(operation_id,caller_principal=caller_principal)

    def apply_retained(self, operation_id, *, caller_principal):
        """Explicitly request high-water application, with no journal ACK on success.

        Obtain a fresh proposal internally, rather than accepting caller-provided
        READY_TO_APPLY objects. The high-water store re-verifies under its own lock.
        A prior receipt is reconciled by local recovery without applying again.
        """
        proposal=self.recover(operation_id,caller_principal=caller_principal)
        if proposal.status!='READY_TO_APPLY': return proposal
        high_water=self.journal._check_high_water()
        result=high_water.apply(proposal.advancement_request,caller_principal=caller_principal)
        return ClientJournalStoreResult(status=result.status,receipt_bytes=result.receipt_bytes)

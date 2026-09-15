"""Pure AppContainer evidence classification for Windows token observations.

This module performs no native calls and grants no admission. The normative
truth table, empirical anchors, unverified rows, and audit/classification signal
boundary are documented in ``docs/TNC_AppContainer_Evidence_Model.md``.
"""
from typing import Literal

from pydantic import Field, model_validator

from tnc.provenance.authorization_models import Model, Identifier
from tnc.provenance.windows_custody_peer import SID


class AppContainerTokenEvidence(Model):
    profile: Literal['tnc-appcontainer-token-evidence-v1'] = 'tnc-appcontainer-token-evidence-v1'
    source: Literal['FAKE_TOKEN_API', 'NATIVE_TOKEN_API']
    token_type: Literal['IMPERSONATION', 'PRIMARY']
    level: Literal['IDENTIFICATION', 'IMPERSONATION', 'DELEGATION'] | None = None
    token_is_app_container: bool = Field(strict=True)
    app_container_sid: SID | None = None
    capability_sids: tuple[SID, ...] = Field(default=(), max_length=256)

    @model_validator(mode='after')
    def valid(self):
        if self.token_type == 'IMPERSONATION' and self.level is None:
            raise ValueError('IMPERSONATION_LEVEL_REQUIRED')
        if self.token_type == 'PRIMARY' and self.level is not None:
            raise ValueError('PRIMARY_TOKEN_HAS_NO_IMPERSONATION_LEVEL')
        if len(set(self.capability_sids)) != len(self.capability_sids):
            raise ValueError('DUPLICATE_CAPABILITY_SID')
        return self


class AppContainerExclusionResult(Model):
    status: Literal['PROVEN_NON_APPCONTAINER', 'APPCONTAINER', 'UNPROVEN', 'INDETERMINATE']
    reason: Identifier
    audit_only: Literal[True] = True
    authorization_granted: Literal[False] = False
    admission_granted: Literal[False] = False


def evaluate_appcontainer_exclusion(evidence):
    """Classify AppContainer evidence without granting peer admission.

    TokenIsAppContainer=0 is sufficient only for PRIMARY tokens and explicitly
    trusted impersonation levels. AppContainer SID/capability facts are treated
    as consistency signals here, not as an independent allow path.
    """
    def result(status, reason):
        return AppContainerExclusionResult(status=status, reason=reason)

    try:
        if type(evidence) is not AppContainerTokenEvidence:
            raise ValueError('EXACT_RECORD_REQUIRED')
        evidence = AppContainerTokenEvidence.model_validate(evidence.model_dump())

        # Any positive native AppContainer indicator is a denial signal. A SID
        # attached to a token reported as non-AppContainer is contradictory and
        # therefore cannot be converted into exclusion proof.
        if evidence.token_is_app_container:
            return result('APPCONTAINER', 'TOKEN_IS_APPCONTAINER')
        if evidence.app_container_sid is not None:
            return result('INDETERMINATE', 'APPCONTAINER_SIGNAL_CONFLICT')

        if evidence.token_type == 'IMPERSONATION' and evidence.level != 'IMPERSONATION':
            # Trusted impersonation levels are explicit. Any level not named as
            # trusted here fails closed by default, including future enum values.
            if evidence.level == 'IDENTIFICATION':
                return result('UNPROVEN', 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN')
            return result('UNPROVEN', 'UNVERIFIED_IMPERSONATION_LEVEL_EXCLUSION_UNPROVEN')

        # Capability observations remain recorded for audit. They do not negate
        # the documented TokenIsAppContainer result and are not themselves used
        # to manufacture admission.
        return result('PROVEN_NON_APPCONTAINER', 'TOKEN_IS_APPCONTAINER_FALSE_USABLE')
    except (ValueError, TypeError, AttributeError):
        return result('INDETERMINATE', 'INVALID_APPCONTAINER_EVIDENCE')

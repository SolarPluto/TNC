"""Pure tests for AppContainer exclusion evidence semantics."""
from typing import Literal, get_args, get_origin

import pytest

from tnc.provenance.windows_appcontainer_evidence import (
    AppContainerTokenEvidence,
    evaluate_appcontainer_exclusion,
)


def evidence(**update):
    data = dict(
        source='NATIVE_TOKEN_API',
        token_type='IMPERSONATION',
        level='IDENTIFICATION',
        token_is_app_container=False,
    )
    data.update(update)
    return AppContainerTokenEvidence(**data)


def _declared_impersonation_levels():
    annotation = AppContainerTokenEvidence.model_fields['level'].annotation
    literal = next(arg for arg in get_args(annotation) if get_origin(arg) is Literal)
    return get_args(literal)


IMPERSONATION_LEVELS = _declared_impersonation_levels()


def test_identification_level_zero_remains_unproven():
    result = evaluate_appcontainer_exclusion(evidence())
    assert result.status == 'UNPROVEN'
    assert result.reason == 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN'
    assert result.audit_only and not result.authorization_granted and not result.admission_granted


@pytest.mark.parametrize(
    'level',
    [level for level in IMPERSONATION_LEVELS if level != 'IMPERSONATION'],
)
def test_every_untrusted_impersonation_level_zero_fails_closed(level):
    result = evaluate_appcontainer_exclusion(evidence(level=level))
    assert result.status == 'UNPROVEN'
    assert not result.authorization_granted and not result.admission_granted


def test_delegation_level_zero_has_level_specific_unproven_reason():
    result = evaluate_appcontainer_exclusion(evidence(level='DELEGATION'))
    assert result.status == 'UNPROVEN'
    assert result.reason == 'DELEGATION_LEVEL_EXCLUSION_UNPROVEN'


def test_impersonation_level_zero_remains_trusted_boundary():
    result = evaluate_appcontainer_exclusion(evidence(level='IMPERSONATION'))
    assert result.status == 'PROVEN_NON_APPCONTAINER'
    assert result.reason == 'TOKEN_IS_APPCONTAINER_FALSE_USABLE'
    assert not result.admission_granted


def test_primary_token_zero_can_prove_non_appcontainer():
    result = evaluate_appcontainer_exclusion(evidence(token_type='PRIMARY', level=None))
    assert result.status == 'PROVEN_NON_APPCONTAINER'
    assert result.reason == 'TOKEN_IS_APPCONTAINER_FALSE_USABLE'


@pytest.mark.parametrize('level', ['IDENTIFICATION', 'IMPERSONATION', 'DELEGATION'])
def test_positive_appcontainer_flag_is_never_exclusion(level):
    result = evaluate_appcontainer_exclusion(evidence(level=level, token_is_app_container=True))
    assert result.status == 'APPCONTAINER'
    assert result.reason == 'TOKEN_IS_APPCONTAINER'
    assert not result.admission_granted


def test_positive_appcontainer_flag_on_primary_token_is_denied():
    result = evaluate_appcontainer_exclusion(
        evidence(token_type='PRIMARY', level=None, token_is_app_container=True)
    )
    assert result.status == 'APPCONTAINER'


def test_nonnull_appcontainer_sid_conflicts_with_zero_flag():
    result = evaluate_appcontainer_exclusion(
        evidence(app_container_sid='S-1-15-2-1')
    )
    assert result.status == 'INDETERMINATE'
    assert result.reason == 'APPCONTAINER_SIGNAL_CONFLICT'


def test_capabilities_do_not_override_identification_level_blocker():
    result = evaluate_appcontainer_exclusion(
        evidence(capability_sids=('S-1-15-3-1',))
    )
    assert result.status == 'UNPROVEN'
    assert result.reason == 'IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN'


def test_capabilities_do_not_manufacture_admission_for_usable_zero():
    result = evaluate_appcontainer_exclusion(
        evidence(level='IMPERSONATION', capability_sids=('S-1-15-3-1',))
    )
    assert result.status == 'PROVEN_NON_APPCONTAINER'
    assert not result.authorization_granted and not result.admission_granted


@pytest.mark.parametrize(
    'kwargs',
    [
        dict(token_type='IMPERSONATION', level=None),
        dict(token_type='PRIMARY', level='IDENTIFICATION'),
        dict(capability_sids=('S-1-15-3-1', 'S-1-15-3-1')),
    ],
)
def test_invalid_evidence_record_rejected_at_model_boundary(kwargs):
    with pytest.raises(ValueError):
        evidence(**kwargs)


def test_wrong_input_type_fails_closed():
    result = evaluate_appcontainer_exclusion({'token_is_app_container': False})
    assert result.status == 'INDETERMINATE'
    assert result.reason == 'INVALID_APPCONTAINER_EVIDENCE'


def test_result_schema_has_no_admitted_state():
    result = evaluate_appcontainer_exclusion(evidence())
    schema = type(result).model_json_schema()
    assert 'ADMITTED' not in schema['properties']['status']['enum']

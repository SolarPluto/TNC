# TNC AppContainer Evidence Model

This document is the evidence specification for `tnc.provenance.windows_appcontainer_evidence`.
It records what the evaluator classifies, which native Windows shapes have actually been
observed, which rows remain assumptions, and which signals are audit-only.

The short summary is **positive AppContainer evidence travels across the tested token levels;
negative evidence is usable only at levels where Windows makes it reliable enough to exclude
AppContainer status.** The table below, not that slogan, is the normative description.

## Status truth table

`capability_sids` is omitted from the decision columns because it does not affect status.
See [Classification signals vs. audit signals](#classification-signals-vs-audit-signals).

| Token type | Level | `TokenIsAppContainer` | AppContainer SID | Status | Reason | Windows observation |
|---|---|---:|---|---|---|---|
| PRIMARY | — | `False` | `None` | `PROVEN_NON_APPCONTAINER` | `TOKEN_IS_APPCONTAINER_FALSE_USABLE` | **Observed** — PR #12 emitted source/restricted/child PRIMARY results |
| PRIMARY | — | `True` | non-null | `APPCONTAINER` | `TOKEN_IS_APPCONTAINER` | **Observed** — PR #8 and PR #11 |
| IMPERSONATION | IDENTIFICATION | `False` | `None` | `UNPROVEN` | `IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN` | **Observed** — PR #7 and PR #12 |
| IMPERSONATION | IDENTIFICATION | `True` | non-null | `APPCONTAINER` | `TOKEN_IS_APPCONTAINER` | **Observed** — PR #8 and PR #11 |
| IMPERSONATION | IMPERSONATION | `False` | `None` | `PROVEN_NON_APPCONTAINER` | `TOKEN_IS_APPCONTAINER_FALSE_USABLE` | **Observed** — PR #9, including hosted Windows Server 2025 replication |
| IMPERSONATION | IMPERSONATION | `True` | non-null | `APPCONTAINER` | `TOKEN_IS_APPCONTAINER` | **Unobserved** — current evaluator would classify this way because a positive flag is checked first |
| IMPERSONATION | DELEGATION | `False` | `None` | `UNPROVEN` | `DELEGATION_LEVEL_EXCLUSION_UNPROVEN` | **Fail-closed default; unverified on Windows** |
| IMPERSONATION | DELEGATION | `True` | non-null | `APPCONTAINER` | `TOKEN_IS_APPCONTAINER` | **Unobserved** |
| any valid token | any valid level | `False` | non-null | `INDETERMINATE` | `APPCONTAINER_SIGNAL_CONFLICT` | **Defensive evaluator behavior; synthetically exercised, not empirically observed from Windows** |
| any valid token | any valid level | `True` | `None` | `APPCONTAINER` | `TOKEN_IS_APPCONTAINER` | **Unobserved** — current evaluator treats the positive flag as sufficient denial evidence even without class-31 SID material |
| invalid evidence record | n/a | n/a | n/a | `INDETERMINATE` | `INVALID_APPCONTAINER_EVIDENCE` | Synthetic validation/error path; not a Windows token shape |

### Trusted impersonation levels are explicit

Negative evidence on an impersonation token is trusted only at levels explicitly named by the
evaluator. Today `IMPERSONATION` is the sole trusted impersonation level, anchored by PR #9.
`IDENTIFICATION` is documented by Windows and observed by PR #7/#12 as unusable for exclusion.
`DELEGATION` has not been empirically anchored, so it now fails closed as `UNPROVEN` rather
than inheriting a permissive fall-through.

This polarity is deliberate: adding a future value to the `level` enum does not make negative
evidence usable merely because the new value exists. A new level must consciously opt in to
the trusted set after documentation or native evidence supports doing so. The safe default is
`UNPROVEN`. Known levels use level-specific reason codes; a future unrecognized enum value
falls back to `UNVERIFIED_LEVEL_EXCLUSION_UNPROVEN` until it is explicitly classified.

## Classification signals vs. audit signals

Only two captured fields affect the current status decision:

- `token_is_app_container` (TokenInformationClass 29), and
- `app_container_sid` (TokenInformationClass 31) as a consistency/conflict signal.

`capability_sids` (TokenInformationClass 30) is **audit-only**. Capability presence is
orthogonal to the AppContainer/non-AppContainer exclusion decision being modeled here, and
using capabilities as an independent allow path would widen authorization semantics without a
need demonstrated by the evidence.

PR #11 nevertheless established a useful native fact: an explicitly requested
`S-1-15-3-1` (`internetClient`) capability survived from the AppContainer PRIMARY token into
the identification-level pipe impersonation token. In the same Windows Server 2025 suite,
the ordinary non-AppContainer identification token had class 30 empty. Thus class 30
discriminated between those **two tested configurations**, but it still does not participate
in the evaluator's classification result.

## Empirical anchors

The observations are samples, not a census of Windows token space.

### PR #7 — ordinary non-AppContainer at IDENTIFICATION

A real ordinary client produced:

- `TokenIsAppContainer=False`
- AppContainer SID `None`
- capability count `0`
- `UNPROVEN / IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN`

This anchored the identification-level negative gate and demonstrated that negative evidence
at that level must not manufacture exclusion proof, admission, or authorization.

### PR #8 — real AppContainer at PRIMARY and IDENTIFICATION

A real AppContainer child was independently verified from its PRIMARY process token, then
observed through the identification-level named-pipe impersonation token. The positive
AppContainer flag and real profile SID remained present, and the evaluator returned
`APPCONTAINER / TOKEN_IS_APPCONTAINER`.

This experiment established a distinct claim: **the APPCONTAINER branch is reachable at
IDENTIFICATION for a real AppContainer client.** The previously considered dead-code
hypothesis was falsified.

### PR #9 — ordinary non-AppContainer at IDENTIFICATION and IMPERSONATION

One ordinary client was observed at both pipe impersonation levels with the same negative
AppContainer evidence shape. The classifier produced:

- IDENTIFICATION -> `UNPROVEN / IDENTIFICATION_LEVEL_EXCLUSION_UNPROVEN`
- IMPERSONATION -> `PROVEN_NON_APPCONTAINER / TOKEN_IS_APPCONTAINER_FALSE_USABLE`

Hosted replication passed on Windows Server 2025 (`10.0.26100`). This is the native anchor for
the negative IMPERSONATION row. It does not extend to DELEGATION, restricted variants, or
AppContainer-positive IMPERSONATION tokens.

### PR #11 — capability-bearing AppContainer at IDENTIFICATION

A real AppContainer child requested `S-1-15-3-1`; the PRIMARY gate verified that the
capability was actually present before the identification experiment began. The same
capability SID appeared on the identification-level impersonation token while class 29 stayed
positive.

This established a claim separate from PR #8: **class 30 capability material can survive
identification-level impersonation.** It did not make capabilities a classification or allow
signal.

### PR #12 — restricted non-AppContainer and same-run level gating

`DISABLE_MAX_PRIVILEGE` reduced a highly privileged runner token to only
`SeChangeNotifyPrivilege` enabled. Source, restricted PRIMARY, child PRIMARY, and
IDENTIFICATION observations all retained the same user SID and the same AppContainer evidence
shape (`False / None / []`). The evaluator classified the PRIMARY observations as
`PROVEN_NON_APPCONTAINER`, but the IDENTIFICATION observation as `UNPROVEN`.

This is the clearest direct demonstration of the level gate: **the same client identity, with
the same flag, SID, and capability evidence, receives a different classification solely
because the token level changes the usability of the negative evidence.**

PR #12 contributes one new empirical pole — a restricted non-AppContainer client observed at
IDENTIFICATION. Its restricted-handle and child-PRIMARY probes are harness/identity checks,
not additional independent samples.

## Current empirical region: sample, not census

The current experimental sequence covers four substantive client/token poles:

1. ordinary non-AppContainer,
2. ordinary AppContainer,
3. capability-bearing AppContainer, and
4. restricted non-AppContainer.

Those samples establish different claims and must not be collapsed into a generic count of
"passing AppContainer tests." In particular, PR #8 established positive-branch reachability,
while PR #11 established capability survival.

Important untested or incompletely tested regions include:

- low-integrity variants,
- service-account tokens,
- network-logon tokens,
- anonymous tokens,
- DELEGATION-level native observations,
- AppContainer-positive IMPERSONATION/DELEGATION observations, and
- the false-flag/non-null-SID conflict (including any sentinel-like SID state such as
  `S-1-15-2-1`).

The conflict/INDETERMINATE path is **defensive evaluator behavior, synthetically exercised,
not empirically observed from Windows**. No known native producer has been demonstrated in
this experiment sequence.

## Policy boundary

Every result produced by this evaluator is audit-only:

- `authorization_granted` is always `False`, and
- `admission_granted` is always `False`.

`APPCONTAINER` is a denial-classification signal, not an admission result.
`PROVEN_NON_APPCONTAINER` is exclusion evidence only; it does not itself establish peer
identity, trust, admission, or authorization.

## Rewrite discipline

Future changes to this model should update the truth table first. Any precommitted
interpretation that depends on a comparison must ensure that both operands are emitted and,
where appropriate, asserted directly by the experiment. Green pytest means the harness and
safety invariants held; experimental claims come from the emitted evidence shape.

When additional native poles are added, label them as samples and identify which previously
unobserved table row or assumption they actually anchor. Do not convert synthetic evaluator
coverage into claims about Windows behavior.

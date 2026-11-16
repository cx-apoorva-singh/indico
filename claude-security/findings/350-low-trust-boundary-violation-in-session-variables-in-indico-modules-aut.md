# Trust Boundary Violation in Session Variables in indico/modules/auth/__init__.py:101

| Field | Value |
|---|---|
| ID | `VG-0133` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/auth/__init__.py:101`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/__init__.py#L101). Engine message: `Trust_Boundary_Violation_in_Session_Variables: first at indico/modules/auth/__init__.py:43 reaches timezone at indico/modules/auth/__init__.py:101`.

```py
   99      """
  100      if user.settings.get('force_timezone'):
  101          session.timezone = user.settings.get('timezone', config.DEFAULT_TIMEZONE)
  102      else:
  103          session.timezone = 'LOCAL'
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/__init__.py:101` and, if so, apply the standard mitigation for CWE-501.

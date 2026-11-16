# Trust Boundary Violation in Session Variables in indico/modules/core/controllers.py:139

| Field | Value |
|---|---|
| ID | `VG-0141` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/core/controllers.py:139`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/core/controllers.py#L139). Engine message: `Trust_Boundary_Violation_in_Session_Variables: form at indico/modules/core/controllers.py:129 reaches set at indico/modules/core/controllers.py:139`.

```py
  137              session.timezone = tz
  138              if update_user and session.user:
  139                  session.user.settings.set('timezone', tz)
  140  
  141          if update_user and session.user:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/core/controllers.py:139` and, if so, apply the standard mitigation for CWE-501.

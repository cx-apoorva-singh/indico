# Trust Boundary Violation in Session Variables in indico/modules/events/api.py:647

| Field | Value |
|---|---|
| ID | `VG-0145` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/api.py:647`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/api.py#L647). Engine message: `Trust_Boundary_Violation_in_Session_Variables: options at indico/modules/events/api.py:488 reaches data at indico/modules/events/api.py:647`.

```py
  645          elif self._detail_level == 'sessions':
  646              data['contributions'] = []
  647              data['sessions'] = []
  648              if allow_details:
  649                  # Contributions without a session
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/api.py:647` and, if so, apply the standard mitigation for CWE-501.

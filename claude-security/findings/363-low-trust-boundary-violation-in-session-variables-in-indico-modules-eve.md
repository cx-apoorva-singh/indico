# Trust Boundary Violation in Session Variables in indico/modules/events/api.py:737

| Field | Value |
|---|---|
| ID | `VG-0146` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/api.py:737`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/api.py#L737). Engine message: `Trust_Boundary_Violation_in_Session_Variables: all at indico/modules/events/api.py:740 reaches sessions at indico/modules/events/api.py:737`.

```py
  735              return []
  736          idlist = set(map(int, idlist))
  737          sessions = (Session.query.with_parent(event)
  738                      .filter(Session.id.in_(idlist),
  739                              ~Session.is_deleted)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/api.py:737` and, if so, apply the standard mitigation for CWE-501.

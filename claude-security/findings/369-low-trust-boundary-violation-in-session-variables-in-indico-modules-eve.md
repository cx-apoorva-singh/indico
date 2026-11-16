# Trust Boundary Violation in Session Variables in indico/modules/events/contributions/controllers/management.py:321

| Field | Value |
|---|---|
| ID | `VG-0152` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/contributions/controllers/management.py:321`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/controllers/management.py#L321). Engine message: `Trust_Boundary_Violation_in_Session_Variables: first at indico/modules/events/contributions/controllers/management.py:323 reaches updates at indico/modules/events/contributions/controllers/management.py:321`.

```py
  319          updates = {}
  320          if session_id is None:
  321              updates['session'] = None
  322          else:
  323              session = Session.query.with_parent(self.event).filter_by(id=session_id).first()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/controllers/management.py:321` and, if so, apply the standard mitigation for CWE-501.

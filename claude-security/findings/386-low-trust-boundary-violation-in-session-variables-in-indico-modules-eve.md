# Trust Boundary Violation in Session Variables in indico/modules/events/sessions/forms.py:50

| Field | Value |
|---|---|
| ID | `VG-0169` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/sessions/forms.py:50`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/forms.py#L50). Engine message: `Trust_Boundary_Violation_in_Session_Variables: with_parent at indico/modules/events/sessions/forms.py:50 reaches query at indico/modules/events/sessions/forms.py:50`.

```py
   48              del self.type
   49          else:
   50              self.type.query = SessionType.query.with_parent(event)
   51              if not self.type.query.has_rows():
   52                  del self.type
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/forms.py:50` and, if so, apply the standard mitigation for CWE-501.

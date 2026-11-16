# Trust Boundary Violation in Session Variables in indico/modules/events/sessions/clone.py:89

| Field | Value |
|---|---|
| ID | `VG-0164` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/sessions/clone.py:89`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/clone.py#L89). Engine message: `Trust_Boundary_Violation_in_Session_Variables: scalar at indico/modules/events/sessions/clone.py:93 reaches _last_friendly_session_id at indico/modules/events/sessions/clone.py:89`.

```py
   87  
   88      def _synchronize_friendly_id(self, new_event):
   89          new_event._last_friendly_session_id = (
   90              db.session
   91              .query(db.func.max(Session.friendly_id))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/clone.py:89` and, if so, apply the standard mitigation for CWE-501.

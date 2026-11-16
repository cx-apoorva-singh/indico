# Trust Boundary Violation in Session Variables in indico/modules/events/sessions/controllers/management/sessions.py:51

| Field | Value |
|---|---|
| ID | `VG-0168` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/sessions/controllers/management/sessions.py:51`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/controllers/management/sessions.py#L51). Engine message: `Trust_Boundary_Violation_in_Session_Variables: all at indico/modules/events/sessions/controllers/management/sessions.py:49 reaches 'sessions' at indico/modules/events/sessions/controllers/management/sessions.py:51`.

```py
   49                  .all())
   50      types = [{'id': t.id, 'title': t.name} for t in event.session_types]
   51      return {'sessions': sessions, 'default_colors': get_colors(), 'types': types}
   52  
   53  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/controllers/management/sessions.py:51` and, if so, apply the standard mitigation for CWE-501.

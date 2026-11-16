# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/controllers/manage.py:76

| Field | Value |
|---|---|
| ID | `VG-0179` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/controllers/manage.py:76`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/controllers/manage.py#L76). Engine message: `Trust_Boundary_Violation_in_Session_Variables: json at indico/modules/events/timetable/controllers/manage.py:92 reaches session_block at indico/modules/events/timetable/controllers/manage.py:76`.

```py
   74          updates['object'] = contribution
   75          if data.get('session_block_id'):
   76              session_block = self.event.get_session_block(data['session_block_id'])
   77              if session_block is None:
   78                  raise BadRequest('Invalid session block id')
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/controllers/manage.py:76` and, if so, apply the standard mitigation for CWE-501.

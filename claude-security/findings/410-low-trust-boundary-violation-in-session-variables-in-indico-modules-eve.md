# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/operations.py:164

| Field | Value |
|---|---|
| ID | `VG-0193` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/operations.py:164`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/operations.py#L164). Engine message: `Trust_Boundary_Violation_in_Session_Variables: json at indico/modules/events/timetable/controllers/legacy.py:441 reaches 'session' at indico/modules/events/timetable/operations.py:164`.

```py
  162          updates['parent'] = parent
  163          updates['start_dt'] = new_start_dt
  164          contrib_update_data = {'session': parent.session_block.session, 'session_block': parent.session_block}
  165  
  166      update_timetable_entry(entry, updates)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/operations.py:164` and, if so, apply the standard mitigation for CWE-501.

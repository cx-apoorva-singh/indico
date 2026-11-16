# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/operations.py:91

| Field | Value |
|---|---|
| ID | `VG-0190` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/operations.py:91`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/operations.py#L91). Engine message: `Trust_Boundary_Violation_in_Session_Variables: one at indico/modules/events/timetable/controllers/manage.py:181 reaches session_block at indico/modules/events/timetable/operations.py:91`.

```py
   89      if session_block:
   90          contribution.session = session_block.session
   91          contribution.session_block = session_block
   92          parent = session_block.timetable_entry
   93      return create_timetable_entry(contribution.event, data, parent=parent, extend_parent=extend_parent)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/operations.py:91` and, if so, apply the standard mitigation for CWE-501.

# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/controllers/manage.py:84

| Field | Value |
|---|---|
| ID | `VG-0180` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/controllers/manage.py:84`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/controllers/manage.py#L84). Engine message: `Trust_Boundary_Violation_in_Session_Variables: first at indico/modules/events/timetable/controllers/manage.py:69 reaches session at indico/modules/events/timetable/controllers/manage.py:84`.

```py
   82                  raise BadRequest('Contribution is assigned to another session')
   83              updates['parent'] = session_block.timetable_entry
   84              contribution.session = session_block.session
   85          else:
   86              updates['object'].session = None
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/controllers/manage.py:84` and, if so, apply the standard mitigation for CWE-501.

# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/operations.py:133

| Field | Value |
|---|---|
| ID | `VG-0192` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/operations.py:133`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/operations.py#L133). Engine message: `Trust_Boundary_Violation_in_Session_Variables: json at indico/modules/events/timetable/controllers/legacy.py:401 reaches 'Session block' at indico/modules/events/timetable/operations.py:133`.

```py
  131          entry.event.log(EventLogRealm.management, LogKind.change, 'Timetable',
  132                          'Session block fitted to contents', session.user,
  133                          data={'Session block': entry.session_block.full_title})
  134  
  135  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/operations.py:133` and, if so, apply the standard mitigation for CWE-501.

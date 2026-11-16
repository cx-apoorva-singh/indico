# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/controllers/legacy.py:57

| Field | Value |
|---|---|
| ID | `VG-0171` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/controllers/legacy.py:57`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/controllers/legacy.py#L57). Engine message: `Trust_Boundary_Violation_in_Session_Variables: args at indico/modules/events/timetable/controllers/legacy.py:59 reaches session_block at indico/modules/events/timetable/controllers/legacy.py:57`.

```py
   55          RHManageTimetableBase._process_args(self)
   56          self.day = dateutil.parser.parse(request.args['day']).date()
   57          self.session_block = None
   58          if 'session_block_id' in request.args:
   59              self.session_block = self.event.get_session_block(request.args['session_block_id'])
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/controllers/legacy.py:57` and, if so, apply the standard mitigation for CWE-501.

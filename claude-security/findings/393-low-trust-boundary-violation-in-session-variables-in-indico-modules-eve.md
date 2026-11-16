# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/controllers/legacy.py:387

| Field | Value |
|---|---|
| ID | `VG-0176` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/controllers/legacy.py:387`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/controllers/legacy.py#L387). Engine message: `Trust_Boundary_Violation_in_Session_Variables: json at indico/modules/events/timetable/controllers/legacy.py:389 reaches session_block at indico/modules/events/timetable/controllers/legacy.py:387`.

```py
  385          self.validate_json(self._json_schema)
  386          self.day = dateutil.parser.parse(request.json['day']).date()
  387          self.session_block = None
  388          if request.json.get('session_block_id') is not None:
  389              self.session_block = self.event.get_session_block(request.json['session_block_id'], scheduled_only=True)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/controllers/legacy.py:387` and, if so, apply the standard mitigation for CWE-501.

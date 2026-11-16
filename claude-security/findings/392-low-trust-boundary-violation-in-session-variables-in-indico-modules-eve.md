# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/controllers/legacy.py:305

| Field | Value |
|---|---|
| ID | `VG-0175` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/controllers/legacy.py:305`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/controllers/legacy.py#L305). Engine message: `Trust_Boundary_Violation_in_Session_Variables: args at indico/modules/events/timetable/controllers/legacy.py:305 reaches session_id at indico/modules/events/timetable/controllers/legacy.py:305`.

```py
  303          self.session_id = None
  304          if 'session_block_id' in request.args:
  305              self.session_id = SessionBlock.get_or_404(request.args['session_block_id']).session_id
  306              if self.session and self.session.id != self.session_id:
  307                  raise BadRequest
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/controllers/legacy.py:305` and, if so, apply the standard mitigation for CWE-501.

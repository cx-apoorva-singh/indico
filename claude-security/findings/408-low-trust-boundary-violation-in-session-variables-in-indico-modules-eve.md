# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/operations.py:128

| Field | Value |
|---|---|
| ID | `VG-0191` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/operations.py:128`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/operations.py#L128). Engine message: `Trust_Boundary_Violation_in_Session_Variables: json at indico/modules/events/timetable/controllers/legacy.py:401 reaches duration at indico/modules/events/timetable/operations.py:128`.

```py
  126      entry.start_dt = min(x.start_dt for x in children)
  127      end_dt = max(x.end_dt for x in children)
  128      entry.session_block.duration = end_dt - entry.start_dt
  129      db.session.flush()
  130      if log:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/operations.py:128` and, if so, apply the standard mitigation for CWE-501.

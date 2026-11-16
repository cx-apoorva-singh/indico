# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/legacy.py:128

| Field | Value |
|---|---|
| ID | `VG-0183` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/legacy.py:128`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/legacy.py#L128). Engine message: `Trust_Boundary_Violation_in_Session_Variables: order_by at indico/modules/events/timetable/legacy.py:45 reaches 'sessionCode' at indico/modules/events/timetable/legacy.py:128`.

```py
  126                       'sessionSlotId': block.id,
  127                       'sessionId': block.session_id,
  128                       'sessionCode': block.session.code,
  129                       'title': block.session.title,
  130                       'slotTitle': block.title,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/legacy.py:128` and, if so, apply the standard mitigation for CWE-501.

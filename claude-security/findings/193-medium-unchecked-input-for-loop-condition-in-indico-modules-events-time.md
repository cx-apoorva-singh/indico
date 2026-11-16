# Unchecked Input for Loop Condition in indico/modules/events/timetable/legacy.py:46

| Field | Value |
|---|---|
| ID | `VG-0340` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/timetable/legacy.py:46`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/legacy.py#L46). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/events/timetable/legacy.py:45 reaches query at indico/modules/events/timetable/legacy.py:46`.

```py
   44                   .options(*query_options)
   45                   .order_by(TimetableEntry.type != TimetableEntryType.SESSION_BLOCK))
   46          for entry in query:
   47              day = entry.start_dt.astimezone(tzinfo).date()
   48              date_str = day.strftime('%Y%m%d')
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/legacy.py:46` and, if so, apply the standard mitigation for CWE-606.

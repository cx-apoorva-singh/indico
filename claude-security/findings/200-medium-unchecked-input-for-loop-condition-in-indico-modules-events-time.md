# Unchecked Input for Loop Condition in indico/modules/events/timetable/util.py:252

| Field | Value |
|---|---|
| ID | `VG-0347` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/timetable/util.py:252`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/util.py#L252). Engine message: `Unchecked_Input_for_Loop_Condition: join at indico/modules/events/timetable/util.py:250 reaches query at indico/modules/events/timetable/util.py:252`.

```py
  250                   .join(TimetableEntry))
  251          if grouped:
  252              for b in query:
  253                  start_date = b.timetable_entry.start_dt.astimezone(tz).date()
  254                  result[b.timetable_entry.event_id]['breaks'][start_date].append((b.timetable_entry, b))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/util.py:252` and, if so, apply the standard mitigation for CWE-606.

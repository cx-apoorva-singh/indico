# Unchecked Input for Loop Condition in indico/modules/events/timetable/util.py:169

| Field | Value |
|---|---|
| ID | `VG-0341` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/timetable/util.py:169`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/util.py#L169). Engine message: `Unchecked_Input_for_Loop_Condition: join at indico/modules/events/timetable/util.py:50 reaches events at indico/modules/events/timetable/util.py:169`.

```py
  167      if from_categ:
  168          events = events.filter(Event.is_visible_in(from_categ.id))
  169      for eid, tt_start_dt in events:
  170          if tt_start_dt:
  171              items[eid][tt_start_dt.astimezone(tz).date()].append(tt_start_dt)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/util.py:169` and, if so, apply the standard mitigation for CWE-606.

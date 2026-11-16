# Unchecked Input for Loop Condition in indico/modules/events/timetable/util.py:244

| Field | Value |
|---|---|
| ID | `VG-0346` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/timetable/util.py:244`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/util.py#L244). Engine message: `Unchecked_Input_for_Loop_Condition: join at indico/modules/events/timetable/util.py:238 reaches query at indico/modules/events/timetable/util.py:244`.

```py
  242                  result[c.event_id]['contribs'][start_date].append((c.timetable_entry, c))
  243          else:
  244              for c in query:
  245                  result[c.event_id]['contributions'].append(c)
  246  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/util.py:244` and, if so, apply the standard mitigation for CWE-606.

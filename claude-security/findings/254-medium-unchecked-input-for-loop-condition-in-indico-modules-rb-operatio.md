# Unchecked Input for Loop Condition in indico/modules/rb/operations/suggestions.py:63

| Field | Value |
|---|---|
| ID | `VG-0401` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/suggestions.py:63`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/suggestions.py#L63). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/rb/operations/bookings.py:82 reaches get at indico/modules/rb/operations/suggestions.py:63`.

```py
   61  
   62          suggestions = {}
   63          taken_periods = [(occ.start_dt, occ.end_dt) for occ in rooms_occurrences.get(room.id, [])]
   64          if room.id in unbookable_hours:
   65              taken_periods.extend((datetime.combine(start_dt, uh.start_time), datetime.combine(end_dt, uh.end_time))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/suggestions.py:63` and, if so, apply the standard mitigation for CWE-606.

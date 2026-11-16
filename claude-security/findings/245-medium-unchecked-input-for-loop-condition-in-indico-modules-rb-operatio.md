# Unchecked Input for Loop Condition in indico/modules/rb/operations/conflicts.py:52

| Field | Value |
|---|---|
| ID | `VG-0392` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/conflicts.py:52`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/conflicts.py#L52). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/rb/operations/conflicts.py:42 reaches items at indico/modules/rb/operations/conflicts.py:52`.

```py
   50      overlapping_occurrences = group_list(query, key=lambda obj: obj.reservation.room.id,
   51                                           sort_by=lambda obj: obj.reservation.room.id)
   52      for room_id, occurrences in overlapping_occurrences.items():
   53          conflicts = get_room_bookings_conflicts(candidates, occurrences, skip_conflicts_with)
   54          rooms_conflicts[room_id], rooms_pre_conflicts[room_id], rooms_conflicting_candidates[room_id] = conflicts
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/conflicts.py:52` and, if so, apply the standard mitigation for CWE-606.

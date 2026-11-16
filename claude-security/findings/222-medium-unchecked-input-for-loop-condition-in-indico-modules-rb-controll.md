# Unchecked Input for Loop Condition in indico/modules/rb/controllers/backend/rooms.py:105

| Field | Value |
|---|---|
| ID | `VG-0369` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/controllers/backend/rooms.py:105`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/controllers/backend/rooms.py#L105). Engine message: `Unchecked_Input_for_Loop_Condition: scalar_subquery at indico/modules/rb/operations/rooms.py:169 reaches rooms at indico/modules/rb/controllers/backend/rooms.py:105`.

```py
  103              # Remove nonoverridable blockings from available rooms
  104              nonoverridable_blocked_rooms_ids = [room.room_id for room in nonoverridable_blocked_rooms]
  105              rooms = [room for room in rooms if room[0] not in nonoverridable_blocked_rooms_ids]
  106          else:
  107              # Add nonoverridable blockings to unavailable rooms and re-sort results
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/controllers/backend/rooms.py:105` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/rb/controllers/backend/rooms.py:108

| Field | Value |
|---|---|
| ID | `VG-0370` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/controllers/backend/rooms.py:108`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/controllers/backend/rooms.py#L108). Engine message: `Unchecked_Input_for_Loop_Condition: scalar_subquery at indico/modules/rb/operations/rooms.py:169 reaches rooms at indico/modules/rb/controllers/backend/rooms.py:108`.

```py
  106          else:
  107              # Add nonoverridable blockings to unavailable rooms and re-sort results
  108              rooms_ids = [room[0] for room in rooms]
  109              missing_rooms = [(room.room_id, room.room.full_name) for room in nonoverridable_blocked_rooms
  110                               if room.room_id not in rooms_ids]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/controllers/backend/rooms.py:108` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/rb/controllers/backend/rooms.py:104

| Field | Value |
|---|---|
| ID | `VG-0368` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/controllers/backend/rooms.py:104`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/controllers/backend/rooms.py#L104). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/operations/blockings.py:73 reaches nonoverridable_blocked_rooms at indico/modules/rb/controllers/backend/rooms.py:104`.

```py
  102          if availability:
  103              # Remove nonoverridable blockings from available rooms
  104              nonoverridable_blocked_rooms_ids = [room.room_id for room in nonoverridable_blocked_rooms]
  105              rooms = [room for room in rooms if room[0] not in nonoverridable_blocked_rooms_ids]
  106          else:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/controllers/backend/rooms.py:104` and, if so, apply the standard mitigation for CWE-606.

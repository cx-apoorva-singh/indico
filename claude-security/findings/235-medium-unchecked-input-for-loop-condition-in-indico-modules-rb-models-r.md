# Unchecked Input for Loop Condition in indico/modules/rb/models/rooms.py:574

| Field | Value |
|---|---|
| ID | `VG-0382` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/models/rooms.py:574`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/models/rooms.py#L574). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/rb/models/rooms.py:573 reaches query at indico/modules/rb/models/rooms.py:574`.

```py
  572                   .filter(~Room.is_deleted, db.or_(*criteria))
  573                   .options(load_only('room_id', 'full_access', 'permissions')))
  574          for principal in query:
  575              is_reservable = principal.room_id not in non_reservable_rooms
  576              for permission in permissions:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/models/rooms.py:574` and, if so, apply the standard mitigation for CWE-606.

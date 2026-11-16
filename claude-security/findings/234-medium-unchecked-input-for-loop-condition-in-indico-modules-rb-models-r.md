# Unchecked Input for Loop Condition in indico/modules/rb/models/rooms.py:550

| Field | Value |
|---|---|
| ID | `VG-0381` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/models/rooms.py:550`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/models/rooms.py#L550). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/rb/models/rooms.py:494 reaches all_rooms_query at indico/modules/rb/models/rooms.py:550`.

```py
  548          non_reservable_rooms = set()
  549          # Set permissions that do not originate from room ACL entries
  550          for room in all_rooms_query:
  551              is_owner = user == room.owner
  552              is_location_manager = room.location.can_manage(user, allow_admin=allow_admin)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/models/rooms.py:550` and, if so, apply the standard mitigation for CWE-606.

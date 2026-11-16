# Unchecked Input for Loop Condition in indico/modules/rb/models/rooms.py:592

| Field | Value |
|---|---|
| ID | `VG-0383` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/models/rooms.py:592`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/models/rooms.py#L592). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/rb/models/rooms.py:590 reaches query at indico/modules/rb/models/rooms.py:592`.

```py
  590                   .options(load_only('location_id', 'full_access', 'permissions'),
  591                            _rooms_strategy))
  592          for principal in query:
  593              for room in principal.location.rooms:
  594                  is_reservable = room.id not in non_reservable_rooms
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/models/rooms.py:592` and, if so, apply the standard mitigation for CWE-606.

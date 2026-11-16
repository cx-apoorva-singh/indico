# Unchecked Input for Loop Condition in indico/modules/rb/models/blocked_rooms.py:108

| Field | Value |
|---|---|
| ID | `VG-0377` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/models/blocked_rooms.py:108`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/models/blocked_rooms.py#L108). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/models/blocked_rooms.py:95 reaches reservations at indico/modules/rb/models/blocked_rooms.py:108`.

```py
  106          reason = f'Conflict with blocking {self.blocking.id}: {self.blocking.reason}'
  107  
  108          for reservation in reservations:
  109              if self.blocking.can_override(reservation.created_by_user, room=reservation.room):
  110                  continue
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/models/blocked_rooms.py:108` and, if so, apply the standard mitigation for CWE-606.

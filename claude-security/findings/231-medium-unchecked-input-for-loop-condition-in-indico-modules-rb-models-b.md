# Unchecked Input for Loop Condition in indico/modules/rb/models/blocked_rooms.py:113

| Field | Value |
|---|---|
| ID | `VG-0378` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/models/blocked_rooms.py:113`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/models/blocked_rooms.py#L113). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/models/blocked_rooms.py:104 reaches occurrences at indico/modules/rb/models/blocked_rooms.py:113`.

```py
  111              reservation.reject(self.blocking.created_by_user, reason)
  112  
  113          for occurrence in occurrences:
  114              reservation = occurrence.reservation
  115              if self.blocking.can_override(reservation.created_by_user, room=reservation.room):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/models/blocked_rooms.py:113` and, if so, apply the standard mitigation for CWE-606.

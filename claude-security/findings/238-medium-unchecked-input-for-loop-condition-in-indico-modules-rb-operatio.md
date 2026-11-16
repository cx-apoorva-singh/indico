# Unchecked Input for Loop Condition in indico/modules/rb/operations/blockings.py:51

| Field | Value |
|---|---|
| ID | `VG-0385` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/blockings.py:51`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/blockings.py#L51). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/operations/blockings.py:73 reaches blocked_rooms at indico/modules/rb/operations/blockings.py:51`.

```py
   49                           allow_admin=False):
   50      if overridable_only:
   51          blocked_rooms = [room for room in blocked_rooms
   52                           if room.blocking.can_override(session.user, room=room.room, explicit_only=explicit,
   53                                                         allow_admin=allow_admin)]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/blockings.py:51` and, if so, apply the standard mitigation for CWE-606.

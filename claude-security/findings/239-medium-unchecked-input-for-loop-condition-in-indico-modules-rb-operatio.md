# Unchecked Input for Loop Condition in indico/modules/rb/operations/blockings.py:55

| Field | Value |
|---|---|
| ID | `VG-0386` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/blockings.py:55`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/blockings.py#L55). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/operations/blockings.py:73 reaches blocked_rooms at indico/modules/rb/operations/blockings.py:55`.

```py
   53                                                         allow_admin=allow_admin)]
   54      if nonoverridable_only:
   55          blocked_rooms = [room for room in blocked_rooms
   56                           if not room.blocking.can_override(session.user, room=room.room, explicit_only=explicit,
   57                                                             allow_admin=allow_admin)]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/blockings.py:55` and, if so, apply the standard mitigation for CWE-606.

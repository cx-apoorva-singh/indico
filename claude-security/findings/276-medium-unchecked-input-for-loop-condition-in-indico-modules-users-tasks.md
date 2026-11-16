# Unchecked Input for Loop Condition in indico/modules/users/tasks.py:32

| Field | Value |
|---|---|
| ID | `VG-0423` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/users/tasks.py:32`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/tasks.py#L32). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/users/tasks.py:31 reaches committing_iterator at indico/modules/users/tasks.py:32`.

```py
   30      else:
   31          users = User.query.filter(~User.is_deleted, User.picture_source == ProfilePictureSource.gravatar).all()
   32      for u in committing_iterator(users):
   33          _do_update_gravatar(u)
   34  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/tasks.py:32` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/rb/operations/rooms.py:93

| Field | Value |
|---|---|
| ID | `VG-0398` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/rooms.py:93`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/rooms.py#L93). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/rb/operations/rooms.py:70 reaches query at indico/modules/rb/operations/rooms.py:93`.

```py
   91      else:
   92          query = _query_all_rooms_for_acl_check()
   93          return {r.id for r in query if r.can_manage(user, permission=permission, explicit_permission=explicit,
   94                                                      allow_admin=False)}
   95  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/rooms.py:93` and, if so, apply the standard mitigation for CWE-606.

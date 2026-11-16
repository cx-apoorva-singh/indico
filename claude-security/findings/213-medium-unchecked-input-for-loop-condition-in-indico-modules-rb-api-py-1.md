# Unchecked Input for Loop Condition in indico/modules/rb/api.py:118

| Field | Value |
|---|---|
| ID | `VG-0360` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/api.py:118`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/api.py#L118). Engine message: `Unchecked_Input_for_Loop_Condition: outerjoin at indico/modules/rb/models/rooms.py:404 reaches rooms_data at indico/modules/rb/api.py:118`.

```py
  116              ])
  117  
  118          for result in rooms_data:
  119              yield _serializable_room(result)
  120  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/api.py:118` and, if so, apply the standard mitigation for CWE-606.

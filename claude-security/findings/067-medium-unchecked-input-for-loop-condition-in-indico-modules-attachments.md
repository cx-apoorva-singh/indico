# Unchecked Input for Loop Condition in indico/modules/attachments/controllers/compat.py:51

| Field | Value |
|---|---|
| ID | `VG-0214` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/attachments/controllers/compat.py:51`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/attachments/controllers/compat.py#L51). Engine message: `Unchecked_Input_for_Loop_Condition: args at indico/modules/attachments/controllers/compat.py:51 reaches items at indico/modules/attachments/controllers/compat.py:51`.

```py
   49                 'subContId': 'subcontrib_id',
   50                 'materialId': 'material_id'}
   51      kwargs = {mapping[k]: v for k, v in request.args.items() if k in mapping}
   52      return compat_folder(**kwargs)
   53  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/attachments/controllers/compat.py:51` and, if so, apply the standard mitigation for CWE-606.

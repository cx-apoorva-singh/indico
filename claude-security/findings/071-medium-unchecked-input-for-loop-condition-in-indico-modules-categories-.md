# Unchecked Input for Loop Condition in indico/modules/categories/controllers/display.py:187

| Field | Value |
|---|---|
| ID | `VG-0218` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/categories/controllers/display.py:187`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/controllers/display.py#L187). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/categories/controllers/display.py:172 reaches query at indico/modules/categories/controllers/display.py:187`.

```py
  185          total_count = query.count()
  186          query = query.limit(10)
  187          return jsonify_data(categories=[serialize_category(c, with_favorite=True, with_path=True) for c in query],
  188                              total_count=total_count, flash=False)
  189  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/controllers/display.py:187` and, if so, apply the standard mitigation for CWE-606.

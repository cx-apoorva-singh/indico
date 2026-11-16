# Unchecked Input for Loop Condition in indico/modules/categories/controllers/management.py:366

| Field | Value |
|---|---|
| ID | `VG-0222` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/categories/controllers/management.py:366`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/controllers/management.py#L366). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/categories/controllers/management.py:356 reaches subcategories at indico/modules/categories/controllers/management.py:366`.

```py
  364              return jsonify_data(flash=False, is_empty=self.category.is_empty)
  365          return jsonify_template('categories/management/delete_categories.html', categories=self.subcategories,
  366                                  category_ids=[x.id for x in self.subcategories])
  367  
  368  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/controllers/management.py:366` and, if so, apply the standard mitigation for CWE-606.

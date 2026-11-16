# Unchecked Input for Loop Condition in indico/modules/categories/controllers/display.py:162

| Field | Value |
|---|---|
| ID | `VG-0217` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/categories/controllers/display.py:162`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/controllers/display.py#L162). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/categories/controllers/display.py:154 reaches categories at indico/modules/categories/controllers/display.py:162`.

```py
  160          excluded_ids = set(excluded_ids) if excluded_ids is not None else set()
  161          categories = self._get_reachable_categories(request.view_args['category_id'], excluded_ids=excluded_ids)
  162          return jsonify_data(categories=[serialize_category_chain(c, include_children=True) for c in categories],
  163                              flash=False)
  164  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/controllers/display.py:162` and, if so, apply the standard mitigation for CWE-606.

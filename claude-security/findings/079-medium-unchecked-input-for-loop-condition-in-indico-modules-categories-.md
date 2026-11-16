# Unchecked Input for Loop Condition in indico/modules/categories/serialize.py:60

| Field | Value |
|---|---|
| ID | `VG-0226` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/categories/serialize.py:60`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/serialize.py#L60). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/categories/serialize.py:49 reaches events at indico/modules/categories/serialize.py:60`.

```py
   58      # make sure the parent categories are in sqlalchemy's identity cache.
   59      # this avoids query spam from `protection_parent` lookups
   60      _parent_categs = (Category._get_chain_query(Category.id.in_({e.category_id for e in events}))  # noqa: F841,RUF100
   61                        .options(load_only('id', 'parent_id', 'protection_mode'),
   62                                 joinedload('acl_entries'))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/serialize.py:60` and, if so, apply the standard mitigation for CWE-606.

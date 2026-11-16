# Second Order SQL Injection in indico/modules/categories/models/categories.py:558

| Field | Value |
|---|---|
| ID | `VG-0122` |
| Severity | **High** |
| Status | open |
| CWE | CWE-89 |
| Rule | `Python_Second_Order_SQL_Injection` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Second_Order_SQL_Injection` (CWE-89) reports an issue at [`indico/modules/categories/models/categories.py:558`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/models/categories.py#L558). Engine message: `Second_Order_SQL_Injection: order_by at indico/modules/categories/serialize.py:49 reaches order_by at indico/modules/categories/models/categories.py:558`.

```py
  556                          .where(Category.id == cte_query.c.parent_id))
  557          cte_query = cte_query.union_all(parent_query)
  558          return Category.query.join(cte_query, Category.id == cte_query.c.id).order_by(cte_query.c.level.desc())
  559  
  560      @property
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/models/categories.py:558` and, if so, apply the standard mitigation for CWE-89.

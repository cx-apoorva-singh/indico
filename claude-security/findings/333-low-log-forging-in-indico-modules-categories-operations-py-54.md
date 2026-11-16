# Log Forging in indico/modules/categories/operations.py:54

| Field | Value |
|---|---|
| ID | `VG-0067` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/categories/operations.py:54`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/operations.py#L54). Engine message: `Log_Forging: values at indico/modules/categories/controllers/management.py:374 reaches info at indico/modules/categories/operations.py:54`.

```py
   52  def move_category(category, target_category):
   53      category.move(target_category)
   54      logger.info('Category %s moved to %s by %s', category, target_category, session.user)
   55  
   56  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/operations.py:54` and, if so, apply the standard mitigation for CWE-117.

# Object Access Violation in indico/modules/events/export.py:194

| Field | Value |
|---|---|
| ID | `VG-0092` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/export.py:194`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/export.py#L194). Engine message: `Object_Access_Violation: f at indico/modules/events/export.py:341 reaches getattr at indico/modules/events/export.py:194`.

```py
  192  def _model_to_table(name):
  193      """Resolve a model name to a full table name (unless it's already one)."""
  194      return getattr(db.m, name).__table__.fullname if name[0].isupper() else name
  195  
  196  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/export.py:194` and, if so, apply the standard mitigation for CWE-99.

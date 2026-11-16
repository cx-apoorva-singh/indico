# Stored Code Injection in indico/modules/events/export.py:525

| Field | Value |
|---|---|
| ID | `VG-0128` |
| Severity | **High** |
| Status | open |
| CWE | CWE-94 |
| Rule | `Python_Stored_Code_Injection` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Stored_Code_Injection` (CWE-94) reports an issue at [`indico/modules/events/export.py:525`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/export.py#L525). Engine message: `Stored_Code_Injection: db at indico/core/db/sqlalchemy/util/models.py:268 reaches eval at indico/modules/events/export.py:525`.

```py
  523              rows_iter = iter(rows)
  524          for row in rows_iter:
  525              if spec['skipif'] and eval(spec['skipif'], _make_globals(ROW=row, CAT_ROLE=cat_role)):  # noqa: S307
  526                  continue
  527              rowdict = row._asdict()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/export.py:525` and, if so, apply the standard mitigation for CWE-94.

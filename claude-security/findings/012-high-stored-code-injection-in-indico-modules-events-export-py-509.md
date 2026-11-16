# Stored Code Injection in indico/modules/events/export.py:509

| Field | Value |
|---|---|
| ID | `VG-0127` |
| Severity | **High** |
| Status | open |
| CWE | CWE-94 |
| Rule | `Python_Stored_Code_Injection` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Stored_Code_Injection` (CWE-94) reports an issue at [`indico/modules/events/export.py:509`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/export.py#L509). Engine message: `Stored_Code_Injection: db at indico/core/db/sqlalchemy/util/models.py:268 reaches eval at indico/modules/events/export.py:509`.

```py
  507              # constraints that require certain objects to be exported before
  508              # the ones referencing them
  509              order = eval(spec['order'], _make_globals())  # noqa: S307
  510              if not isinstance(order, tuple):
  511                  order = (order,)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/export.py:509` and, if so, apply the standard mitigation for CWE-94.

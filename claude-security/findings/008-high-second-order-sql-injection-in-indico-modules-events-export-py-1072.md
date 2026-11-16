# Second Order SQL Injection in indico/modules/events/export.py:1072

| Field | Value |
|---|---|
| ID | `VG-0123` |
| Severity | **High** |
| Status | open |
| CWE | CWE-89 |
| Rule | `Python_Second_Order_SQL_Injection` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Second_Order_SQL_Injection` (CWE-89) reports an issue at [`indico/modules/events/export.py:1072`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/export.py#L1072). Engine message: `Second_Order_SQL_Injection: f at indico/modules/events/export.py:644 reaches execute at indico/modules/events/export.py:1072`.

```py
 1070              fmt = self.spec['verbose'][table.fullname]
 1071              click.echo(fmt.format(**insert_values))
 1072          res = db.session.execute(table.insert(), insert_values)
 1073          if set_idref is not None:
 1074              # if a column was marked as having incoming FKs, store
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/export.py:1072` and, if so, apply the standard mitigation for CWE-89.

# Object Access Violation in indico/core/db/sqlalchemy/util/models.py:190

| Field | Value |
|---|---|
| ID | `VG-0086` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/core/db/sqlalchemy/util/models.py:190`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/db/sqlalchemy/util/models.py#L190). Engine message: `Object_Access_Violation: scalar at indico/core/db/sqlalchemy/util/models.py:189 reaches setattr at indico/core/db/sqlalchemy/util/models.py:190`.

```py
  188          with db.session.no_autoflush:
  189              id_ = db.session.query(db.func.nextval(db.func.pg_get_serial_sequence(table_name, col_name))).scalar()
  190          setattr(self, attr_name, id_)
  191  
  192      def populate_from_dict(self, data, keys=None, skip=None, track_changes=True):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/db/sqlalchemy/util/models.py:190` and, if so, apply the standard mitigation for CWE-99.

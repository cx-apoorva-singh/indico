# Unchecked Input for Loop Condition in indico/core/db/sqlalchemy/principals.py:518

| Field | Value |
|---|---|
| ID | `VG-0211` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/core/db/sqlalchemy/principals.py:518`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/db/sqlalchemy/principals.py#L518). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/core/db/sqlalchemy/principals.py:517 reaches query at indico/core/db/sqlalchemy/principals.py:518`.

```py
  516                   .filter(cls.email.in_(user.all_emails))
  517                   .options(noload('user'), noload('local_group'), joinedload(relationship_attr).load_only('id')))
  518          for entry in query:
  519              parent = getattr(entry, relationship_attr)
  520              existing = (cls.query
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/db/sqlalchemy/principals.py:518` and, if so, apply the standard mitigation for CWE-606.

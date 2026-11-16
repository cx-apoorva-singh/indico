# Hardcoded Password in Connection String in indico/cli/setup.py:465

| Field | Value |
|---|---|
| ID | `VG-0061` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-547 |
| Rule | `Python_Hardcoded_Password_in_Connection_String` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Hardcoded_Password_in_Connection_String` (CWE-547) reports an issue at [`indico/cli/setup.py:465`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/cli/setup.py#L465). Engine message: `Hardcoded_Password_in_Connection_String: "postgresql://user:pass@host/indico"`.

```py
  463              default = 'postgresql:///indico'
  464          else:
  465              default = 'postgresql://user:pass@host/indico'
  466          self.db_uri = _prompt('PostgreSQL database URI', default=default,
  467                                validate=_check_postgres, allow_invalid=True,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/cli/setup.py:465` and, if so, apply the standard mitigation for CWE-547.

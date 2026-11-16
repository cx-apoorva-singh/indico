# Filtering Sensitive Logs in indico/modules/auth/providers.py:33

| Field | Value |
|---|---|
| ID | `VG-0054` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/modules/auth/providers.py:33`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/providers.py#L33). Engine message: `Filtering_Sensitive_Logs: auth at indico/modules/auth/providers.py:15 reaches warning at indico/modules/auth/providers.py:33`.

```py
   31              return False
   32          if error := validate_secure_password('login', password, username=identity.identifier, fast=True):
   33              logger.warning('Account %s logged in with an insecure password: %s', identity.identifier, error)
   34              session['insecure_password_error'] = error
   35          return True
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/providers.py:33` and, if so, apply the standard mitigation for CWE-532.

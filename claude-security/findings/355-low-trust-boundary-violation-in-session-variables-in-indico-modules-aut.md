# Trust Boundary Violation in Session Variables in indico/modules/auth/providers.py:34

| Field | Value |
|---|---|
| ID | `VG-0138` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/auth/providers.py:34`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/providers.py#L34). Engine message: `Trust_Boundary_Violation_in_Session_Variables: all at indico/modules/auth/providers.py:56 reaches session at indico/modules/auth/providers.py:34`.

```py
   32          if error := validate_secure_password('login', password, username=identity.identifier, fast=True):
   33              logger.warning('Account %s logged in with an insecure password: %s', identity.identifier, error)
   34              session['insecure_password_error'] = error
   35          return True
   36  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/providers.py:34` and, if so, apply the standard mitigation for CWE-501.

# Trust Boundary Violation in Session Variables in indico/modules/auth/util.py:25

| Field | Value |
|---|---|
| ID | `VG-0139` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/auth/util.py:25`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/util.py#L25). Engine message: `Trust_Boundary_Violation_in_Session_Variables: all at indico/modules/auth/__init__.py:50 reaches session at indico/modules/auth/util.py:25`.

```py
   23      """Save information from IdentityInfo in the session."""
   24      trusted_email = identity_info.provider.settings.get('trusted_email', False)
   25      session['login_identity_info'] = {
   26          'provider': identity_info.provider.name,
   27          'provider_title': identity_info.provider.title,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/util.py:25` and, if so, apply the standard mitigation for CWE-501.

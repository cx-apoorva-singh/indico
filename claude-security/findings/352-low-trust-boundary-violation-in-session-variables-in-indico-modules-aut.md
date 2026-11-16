# Trust Boundary Violation in Session Variables in indico/modules/auth/__init__.py:105

| Field | Value |
|---|---|
| ID | `VG-0135` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/auth/__init__.py:105`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/__init__.py#L105). Engine message: `Trust_Boundary_Violation_in_Session_Variables: first at indico/modules/auth/__init__.py:43 reaches lang at indico/modules/auth/__init__.py:105`.

```py
  103          session.timezone = 'LOCAL'
  104      session.set_session_user(user)
  105      session.lang = user.settings.get('lang')
  106      if not admin_impersonation:
  107          if identity:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/__init__.py:105` and, if so, apply the standard mitigation for CWE-501.

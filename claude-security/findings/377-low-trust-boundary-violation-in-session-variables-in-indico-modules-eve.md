# Trust Boundary Violation in Session Variables in indico/modules/events/sessions/__init__.py:54

| Field | Value |
|---|---|
| ID | `VG-0160` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/sessions/__init__.py:54`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/__init__.py#L54). Engine message: `Trust_Boundary_Violation_in_Session_Variables: options at indico/core/db/sqlalchemy/principals.py:517 reaches sessions at indico/modules/events/sessions/__init__.py:54`.

```py
   52  def _convert_email_principals(user, silent=False, **kwargs):
   53      from indico.modules.events.sessions.models.principals import SessionPrincipal
   54      sessions = SessionPrincipal.replace_email_with_user(user, 'session')
   55      if sessions and not silent:
   56          num = len(sessions)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/__init__.py:54` and, if so, apply the standard mitigation for CWE-501.

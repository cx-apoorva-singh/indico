# Filtering Sensitive Logs in indico/modules/auth/controllers.py:396

| Field | Value |
|---|---|
| ID | `VG-0050` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/modules/auth/controllers.py:396`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/controllers.py#L396). Engine message: `Filtering_Sensitive_Logs: auth at indico/modules/auth/controllers.py:27 reaches info at indico/modules/auth/controllers.py:396`.

```py
  394              self.user.local_identity.password = form.new_password.data
  395              session.pop('insecure_password_error', None)
  396              logger.info('User %s (%s) changed their password', self.user, self.user.local_identity.identifier)
  397              self.user.log(UserLogRealm.user, LogKind.change, 'Accounts', 'Password changed', session.user)
  398          flash(_('Your local account credentials have been updated successfully'), 'success')
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/controllers.py:396` and, if so, apply the standard mitigation for CWE-532.

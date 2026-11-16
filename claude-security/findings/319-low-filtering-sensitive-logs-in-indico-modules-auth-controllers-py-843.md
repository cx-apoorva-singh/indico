# Filtering Sensitive Logs in indico/modules/auth/controllers.py:843

| Field | Value |
|---|---|
| ID | `VG-0052` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/modules/auth/controllers.py:843`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/controllers.py#L843). Engine message: `Filtering_Sensitive_Logs: auth at indico/modules/auth/controllers.py:27 reaches info at indico/modules/auth/controllers.py:843`.

```py
  841              identity.user.log(UserLogRealm.user, LogKind.change, 'Accounts', 'Password reset', session.user,
  842                                data={'IP': request.remote_addr})
  843              logger.info('Password reset confirmed for user %s', identity.user)
  844              # We usually come here from a multipass login page so we should have a target url
  845              return multipass.redirect_success()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/controllers.py:843` and, if so, apply the standard mitigation for CWE-532.

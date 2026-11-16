# Filtering Sensitive Logs in indico/modules/auth/controllers.py:387

| Field | Value |
|---|---|
| ID | `VG-0049` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/modules/auth/controllers.py:387`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/controllers.py#L387). Engine message: `Filtering_Sensitive_Logs: auth at indico/modules/auth/controllers.py:27 reaches info at indico/modules/auth/controllers.py:387`.

```py
  385          self.user.log(UserLogRealm.user, LogKind.positive, 'Accounts', 'Local account created', session.user,
  386                        data={'Identifier': identifier})
  387          logger.info('User %s added a local account (%s)', self.user, identity.identifier)
  388          flash(_('Local account added successfully'), 'success')
  389  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/controllers.py:387` and, if so, apply the standard mitigation for CWE-532.

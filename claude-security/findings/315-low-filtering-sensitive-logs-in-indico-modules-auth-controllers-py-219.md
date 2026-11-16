# Filtering Sensitive Logs in indico/modules/auth/controllers.py:219

| Field | Value |
|---|---|
| ID | `VG-0048` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/modules/auth/controllers.py:219`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/controllers.py#L219). Engine message: `Filtering_Sensitive_Logs: auth at indico/modules/auth/controllers.py:27 reaches info at indico/modules/auth/controllers.py:219`.

```py
  217                        data={'Provider': multipass.identity_providers[identity.provider].title,
  218                              'Identifier': identity.identifier})
  219          logger.info('Created new identity for %s: %s', self.user, identity)
  220          del session['login_identity_info']
  221          db.session.flush()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/controllers.py:219` and, if so, apply the standard mitigation for CWE-532.

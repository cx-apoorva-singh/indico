# Filtering Sensitive Logs in indico/modules/auth/util.py:97

| Field | Value |
|---|---|
| ID | `VG-0056` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/modules/auth/util.py:97`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/auth/util.py#L97). Engine message: `Filtering_Sensitive_Logs: auth at indico/modules/auth/util.py:88 reaches info at indico/modules/auth/util.py:97`.

```py
   95          return
   96      user = User.get_or_404(entry['user_id'])
   97      logger.info('Admin %r stopped impersonating user %r', user, session.user)
   98      session.set_session_user(user)
   99      session.update(entry['session_data'])
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/auth/util.py:97` and, if so, apply the standard mitigation for CWE-532.

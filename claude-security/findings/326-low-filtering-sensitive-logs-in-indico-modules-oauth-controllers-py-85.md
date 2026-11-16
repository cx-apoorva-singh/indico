# Filtering Sensitive Logs in indico/modules/oauth/controllers.py:85

| Field | Value |
|---|---|
| ID | `VG-0059` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/modules/oauth/controllers.py:85`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/oauth/controllers.py#L85). Engine message: `Filtering_Sensitive_Logs: auth_server at indico/modules/oauth/controllers.py:76 reaches info at indico/modules/oauth/controllers.py:85`.

```py
   83              if 'confirm' not in request.form:
   84                  return False
   85              logger.info('User %s authorized %s', session.user, application)
   86              return True
   87          elif application.is_trusted:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/oauth/controllers.py:85` and, if so, apply the standard mitigation for CWE-532.

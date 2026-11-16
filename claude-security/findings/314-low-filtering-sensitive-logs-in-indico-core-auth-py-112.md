# Filtering Sensitive Logs in indico/core/auth.py:112

| Field | Value |
|---|---|
| ID | `VG-0047` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/core/auth.py:112`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/auth.py#L112). Engine message: `Filtering_Sensitive_Logs: InvalidCredentials at indico/core/auth.py:126 reaches warning at indico/core/auth.py:112`.

```py
  110              if not getattr(exc, '_indico_no_rate_limit', False):
  111                  login_rate_limiter.hit()
  112              logger.warning('Invalid credentials (ip=%s, provider=%s): %s',
  113                             request.remote_addr, exc.provider.name if exc.provider else None, exc)
  114          else:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/auth.py:112` and, if so, apply the standard mitigation for CWE-532.

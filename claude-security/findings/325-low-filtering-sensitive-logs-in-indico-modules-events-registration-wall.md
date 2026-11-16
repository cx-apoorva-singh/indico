# Filtering Sensitive Logs in indico/modules/events/registration/wallets/google.py:113

| Field | Value |
|---|---|
| ID | `VG-0058` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-532 |
| Rule | `Python_Filtering_Sensitive_Logs` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Filtering_Sensitive_Logs` (CWE-532) reports an issue at [`indico/modules/events/registration/wallets/google.py:113`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/wallets/google.py#L113). Engine message: `Filtering_Sensitive_Logs: AuthorizedSession at indico/modules/events/registration/wallets/google.py:109 reaches info at indico/modules/events/registration/wallets/google.py:113`.

```py
  111          if resp.ok:
  112              return GoogleCredentialValidationResult.ok
  113          logger.info('Could not validate GCP credentials (%d): %s', resp.status_code, resp.text)
  114          if resp.status_code == 403:
  115              return GoogleCredentialValidationResult.refused
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/wallets/google.py:113` and, if so, apply the standard mitigation for CWE-532.

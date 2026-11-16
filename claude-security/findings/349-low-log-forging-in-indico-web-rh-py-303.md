# Log Forging in indico/web/rh.py:303

| Field | Value |
|---|---|
| ID | `VG-0083` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/web/rh.py:303`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/rh.py#L303). Engine message: `Log_Forging: method at indico/web/rh.py:304 reaches info at indico/web/rh.py:303`.

```py
  301              self._check_event_feature()
  302  
  303          logger.info('%s %s [IP=%s] [PID=%s]',
  304                      request.method, request.relative_url, request.remote_addr, os.getpid())
  305  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/rh.py:303` and, if so, apply the standard mitigation for CWE-117.

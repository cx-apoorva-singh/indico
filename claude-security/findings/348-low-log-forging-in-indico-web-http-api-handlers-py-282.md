# Log Forging in indico/web/http_api/handlers.py:282

| Field | Value |
|---|---|
| ID | `VG-0082` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/web/http_api/handlers.py:282`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/http_api/handlers.py#L282). Engine message: `Log_Forging: query_string at indico/web/http_api/handlers.py:118 reaches exception at indico/web/http_api/handlers.py:282`.

```py
  280              return response
  281          except Exception:
  282              logger.exception('Serialization error in request %s?%s', path, query)
  283              raise
  284  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/http_api/handlers.py:282` and, if so, apply the standard mitigation for CWE-117.

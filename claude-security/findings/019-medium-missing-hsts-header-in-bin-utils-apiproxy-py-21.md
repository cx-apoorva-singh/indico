# Missing HSTS Header in bin/utils/apiProxy.py:21

| Field | Value |
|---|---|
| ID | `VG-0084` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-346 |
| Rule | `Python_Missing_HSTS_Header` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Missing_HSTS_Header` (CWE-346) reports an issue at [`bin/utils/apiProxy.py:21`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/utils/apiProxy.py#L21). Engine message: `Missing_HSTS_Header: app`.

```py
   19  
   20  
   21  app = Flask(__name__)
   22  
   23  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/utils/apiProxy.py:21` and, if so, apply the standard mitigation for CWE-346.

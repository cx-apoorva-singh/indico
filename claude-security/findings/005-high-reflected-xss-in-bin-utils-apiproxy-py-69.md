# Reflected XSS in bin/utils/apiProxy.py:69

| Field | Value |
|---|---|
| ID | `VG-0118` |
| Severity | **High** |
| Status | open |
| CWE | CWE-79 |
| Rule | `Python_Reflected_XSS` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Reflected_XSS` (CWE-79) reports an issue at [`bin/utils/apiProxy.py:69`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/utils/apiProxy.py#L69). Engine message: `Reflected_XSS: values at bin/utils/apiProxy.py:40 reaches at bin/utils/apiProxy.py:69`.

```py
   67          print('WARNING: Did not receive a content type, falling back to text/plain')
   68          content_type = 'text/plain'
   69      return Response(resp, mimetype=content_type)
   70  
   71  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/utils/apiProxy.py:69` and, if so, apply the standard mitigation for CWE-79.

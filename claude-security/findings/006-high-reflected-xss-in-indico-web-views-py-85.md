# Reflected XSS in indico/web/views.py:85

| Field | Value |
|---|---|
| ID | `VG-0119` |
| Severity | **High** |
| Status | open |
| CWE | CWE-79 |
| Rule | `Python_Reflected_XSS` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Reflected_XSS` (CWE-79) reports an issue at [`indico/web/views.py:85`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/views.py#L85). Engine message: `Reflected_XSS: local_tz at indico/web/views.py:29 reaches Markup at indico/web/views.py:85`.

```py
   83                                  force_locale=force_locale,
   84                                  force_locale_alts=force_locale_alts)
   85      return Markup(rv)
   86  
   87  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/views.py:85` and, if so, apply the standard mitigation for CWE-79.

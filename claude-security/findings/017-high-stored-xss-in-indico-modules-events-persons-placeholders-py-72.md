# Stored XSS in indico/modules/events/persons/placeholders.py:72

| Field | Value |
|---|---|
| ID | `VG-0132` |
| Severity | **High** |
| Status | open |
| CWE | CWE-79 |
| Rule | `Python_Stored_XSS` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Stored_XSS` (CWE-79) reports an issue at [`indico/modules/events/persons/placeholders.py:72`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/persons/placeholders.py#L72). Engine message: `Stored_XSS: all at indico/modules/events/contributions/util.py:245 reaches Markup at indico/modules/events/persons/placeholders.py:72`.

```py
   70              event.timezone
   71          )
   72          return Markup(html)
   73  
   74  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/persons/placeholders.py:72` and, if so, apply the standard mitigation for CWE-79.

# Trust Boundary Violation in Session Variables in indico/modules/core/controllers.py:156

| Field | Value |
|---|---|
| ID | `VG-0143` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/core/controllers.py:156`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/core/controllers.py#L156). Engine message: `Trust_Boundary_Violation_in_Session_Variables: form at indico/modules/core/controllers.py:151 reaches set at indico/modules/core/controllers.py:156`.

```py
  154          session.lang = language
  155          if session.user:
  156              session.user.settings.set('lang', language)
  157          return '', 204
  158  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/core/controllers.py:156` and, if so, apply the standard mitigation for CWE-501.

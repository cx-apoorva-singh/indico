# Object Access Violation in indico/web/rh.py:214

| Field | Value |
|---|---|
| ID | `VG-0113` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/web/rh.py:214`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/rh.py#L214). Engine message: `Object_Access_Violation: method at indico/web/rh.py:214 reaches getattr at indico/web/rh.py:214`.

```py
  212          override this method, especially when using WTForms.
  213          """
  214          method = getattr(self, '_process_' + request.method, None)
  215          if method is None:
  216              valid_methods = [m for m in HTTP_VERBS if hasattr(self, '_process_' + m)]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/rh.py:214` and, if so, apply the standard mitigation for CWE-99.

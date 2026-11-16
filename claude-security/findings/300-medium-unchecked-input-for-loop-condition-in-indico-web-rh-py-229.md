# Unchecked Input for Loop Condition in indico/web/rh.py:229

| Field | Value |
|---|---|
| ID | `VG-0447` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/rh.py:229`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/rh.py#L229). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/web/rh.py:229 reaches items at indico/web/rh.py:229`.

```py
  227          if token is None:
  228              # Might be a WTForm with a prefix. In that case the field name is '<prefix>-csrf_token'
  229              token = next((v for k, v in request.form.items() if k.endswith('-csrf_token')), None)
  230          if self.CSRF_ENABLED and request.method != 'GET' and token != session.csrf_token:
  231              msg = _("It looks like there was a problem with your current session. Please use your browser's back "
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/rh.py:229` and, if so, apply the standard mitigation for CWE-606.

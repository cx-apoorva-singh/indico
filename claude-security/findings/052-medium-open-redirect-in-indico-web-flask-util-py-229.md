# Open Redirect in indico/web/flask/util.py:229

| Field | Value |
|---|---|
| ID | `VG-0117` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-601 |
| Rule | `Python_Open_Redirect` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Open_Redirect` (CWE-601) reports an issue at [`indico/web/flask/util.py:229`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/flask/util.py#L229). Engine message: `Open_Redirect: url at indico/core/plugins/controllers.py:65 reaches redirect at indico/web/flask/util.py:229`.

```py
  227          return jsonify_data(flash=flash, **json_data)
  228      else:
  229          return redirect(location)
  230  
  231  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=Y). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/flask/util.py:229` and, if so, apply the standard mitigation for CWE-601.

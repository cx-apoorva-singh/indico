# Open Redirect in indico/web/flask/util.py:106

| Field | Value |
|---|---|
| ID | `VG-0116` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-601 |
| Rule | `Python_Open_Redirect` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Open_Redirect` (CWE-601) reports an issue at [`indico/web/flask/util.py:106`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/flask/util.py#L106). Engine message: `Open_Redirect: code at indico/web/flask/util.py:102 reaches redirect at indico/web/flask/util.py:106`.

```py
  104      def _redirect(**kwargs):
  105          params = request.args.to_dict() | kwargs
  106          return redirect(_url_for(endpoint, **params), code=code)
  107  
  108      return _redirect
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=Y). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/flask/util.py:106` and, if so, apply the standard mitigation for CWE-601.

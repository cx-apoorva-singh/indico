# Unchecked Input for Loop Condition in indico/web/rh.py:179

| Field | Value |
|---|---|
| ID | `VG-0446` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/rh.py:179`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/rh.py#L179). Engine message: `Unchecked_Input_for_Loop_Condition: args at indico/web/rh.py:179 reaches items at indico/web/rh.py:179`.

```py
  177          provided = {k: _convert(v) for k, v in request.view_args.items() if k not in defaults}
  178          if spec['copy_query_args']:
  179              provided.update((k, _convert(v)) for k, v in request.args.items() if k in spec['copy_query_args'])
  180          new_view_args = {k: _convert(v) for k, v in new_view_args.items() if v is not None}
  181          if new_view_args != provided:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/rh.py:179` and, if so, apply the standard mitigation for CWE-606.

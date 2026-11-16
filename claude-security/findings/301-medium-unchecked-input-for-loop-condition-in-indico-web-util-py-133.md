# Unchecked Input for Loop Condition in indico/web/util.py:133

| Field | Value |
|---|---|
| ID | `VG-0448` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/util.py:133`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/util.py#L133). Engine message: `Unchecked_Input_for_Loop_Condition: args at indico/web/util.py:170 reaches items at indico/web/util.py:133`.

```py
  131  def _format_request_data(data, *, hide_passwords=False, strip_session_cookie=False):
  132      if not hasattr(data, 'lists'):
  133          data = ((k, [v]) for k, v in data.items())
  134      else:
  135          data = data.lists()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/util.py:133` and, if so, apply the standard mitigation for CWE-606.

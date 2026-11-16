# Unchecked Input for Loop Condition in indico/web/flask/util.py:119

| Field | Value |
|---|---|
| ID | `VG-0437` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/flask/util.py:119`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/flask/util.py#L119). Engine message: `Unchecked_Input_for_Loop_Condition: args at indico/web/flask/util.py:119 reaches lists at indico/web/flask/util.py:119`.

```py
  117          # Ugly hack to get non-list arguments unless they are used multiple times.
  118          # This is necessary since passing a list for an URL path argument breaks things.
  119          view_args.update((k, v[0] if len(v) == 1 else v) for k, v in request.args.lists())
  120          if view_args_conv is not None:
  121              for oldkey, newkey in view_args_conv.items():
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/flask/util.py:119` and, if so, apply the standard mitigation for CWE-606.

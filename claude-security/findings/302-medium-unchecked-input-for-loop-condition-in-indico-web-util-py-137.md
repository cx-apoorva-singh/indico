# Unchecked Input for Loop Condition in indico/web/util.py:137

| Field | Value |
|---|---|
| ID | `VG-0449` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/util.py:137`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/util.py#L137). Engine message: `Unchecked_Input_for_Loop_Condition: args at indico/web/util.py:170 reaches data at indico/web/util.py:137`.

```py
  135          data = data.lists()
  136      rv = {}
  137      for key, values in data:
  138          if hide_passwords and 'password' in key:
  139              values = [v if not v else f'<{len(v)} chars hidden>' for v in values]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/util.py:137` and, if so, apply the standard mitigation for CWE-606.

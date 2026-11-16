# Unchecked Input for Loop Condition in indico/modules/logs/controllers.py:38

| Field | Value |
|---|---|
| ID | `VG-0356` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/logs/controllers.py:38`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/logs/controllers.py#L38). Engine message: `Unchecked_Input_for_Loop_Condition: args at indico/modules/logs/controllers.py:38 reaches items at indico/modules/logs/controllers.py:38`.

```py
   36  def _get_metadata_query():
   37      return {k[len('meta.'):]: int(v) if v.isdigit() else v
   38              for k, v in request.args.items()
   39              if k.startswith('meta.')}
   40  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/logs/controllers.py:38` and, if so, apply the standard mitigation for CWE-606.

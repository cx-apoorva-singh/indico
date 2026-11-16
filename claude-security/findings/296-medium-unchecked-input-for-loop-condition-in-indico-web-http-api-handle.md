# Unchecked Input for Loop Condition in indico/web/http_api/handlers.py:51

| Field | Value |
|---|---|
| ID | `VG-0443` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/http_api/handlers.py:51`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/http_api/handlers.py#L51). Engine message: `Unchecked_Input_for_Loop_Condition: query_string at indico/web/http_api/handlers.py:118 reaches sorted at indico/web/http_api/handlers.py:51`.

```py
   49      sorted_params = []
   50  
   51      for key, values in sorted(qparams.items(), key=lambda x: x[0].lower()):
   52          key = key.lower()
   53          if key not in remove:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/http_api/handlers.py:51` and, if so, apply the standard mitigation for CWE-606.

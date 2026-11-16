# Unchecked Input for Loop Condition in indico/web/http_api/handlers.py:114

| Field | Value |
|---|---|
| ID | `VG-0444` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/http_api/handlers.py:114`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/http_api/handlers.py#L114). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/web/http_api/handlers.py:108 reaches queryParams at indico/web/http_api/handlers.py:114`.

```py
  112          # if you write a new api endpoint that needs multiple values get them from
  113          # ``request.values.getlist()`` directly
  114          queryParams = {key: values[0] for key, values in queryParams}
  115      else:
  116          # Parse the actual query string
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/http_api/handlers.py:114` and, if so, apply the standard mitigation for CWE-606.

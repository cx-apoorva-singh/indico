# Unchecked Input for Loop Condition in indico/web/flask/app.py:376

| Field | Value |
|---|---|
| ID | `VG-0436` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/flask/app.py:376`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/flask/app.py#L376). Engine message: `Unchecked_Input_for_Loop_Condition: values at indico/web/flask/app.py:376 reaches lists at indico/web/flask/app.py:376`.

```py
  374  
  375  def reject_nuls():
  376      for key, values in request.values.lists():
  377          if '\0' in key or any('\0' in x for x in values):
  378              raise BadRequest('NUL byte found in request data')
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/flask/app.py:376` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/events/papers/fields.py:28

| Field | Value |
|---|---|
| ID | `VG-0284` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/papers/fields.py:28`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/papers/fields.py#L28). Engine message: `Unchecked_Input_for_Loop_Condition: loads at indico/modules/events/papers/fields.py:26 reaches items at indico/modules/events/papers/fields.py:28`.

```py
   26              self.data = json.loads(valuelist[0])
   27              data = {}
   28              for key, value in self.data.items():
   29                  data[key] = RoleConverter.to_python(value) if isinstance(value, list) else value
   30              self.data = data
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/papers/fields.py:28` and, if so, apply the standard mitigation for CWE-606.

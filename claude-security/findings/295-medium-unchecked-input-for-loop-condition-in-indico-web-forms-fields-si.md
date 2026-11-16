# Unchecked Input for Loop Condition in indico/web/forms/fields/simple.py:188

| Field | Value |
|---|---|
| ID | `VG-0442` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/forms/fields/simple.py:188`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/forms/fields/simple.py#L188). Engine message: `Unchecked_Input_for_Loop_Condition: loads at indico/web/forms/fields/simple.py:185 reaches data at indico/web/forms/fields/simple.py:188`.

```py
  186  
  187      def _value(self, for_react=False):
  188          return [{'id': d, 'name': d} for d in self.data] if for_react else self.data
  189  
  190  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/forms/fields/simple.py:188` and, if so, apply the standard mitigation for CWE-606.

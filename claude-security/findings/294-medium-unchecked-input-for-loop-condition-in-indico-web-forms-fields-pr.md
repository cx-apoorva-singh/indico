# Unchecked Input for Loop Condition in indico/web/forms/fields/principals.py:103

| Field | Value |
|---|---|
| ID | `VG-0441` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/forms/fields/principals.py:103`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/forms/fields/principals.py#L103). Engine message: `Unchecked_Input_for_Loop_Condition: loads at indico/web/forms/fields/principals.py:102 reaches _submitted_data at indico/web/forms/fields/principals.py:103`.

```py
  101          if valuelist:
  102              self._submitted_data = json.loads(valuelist[0])
  103              self.data = {self._convert_principal(x) for x in self._submitted_data}
  104  
  105      def _value(self):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/forms/fields/principals.py:103` and, if so, apply the standard mitigation for CWE-606.

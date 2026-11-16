# Unchecked Input for Loop Condition in indico/web/forms/fields/files.py:109

| Field | Value |
|---|---|
| ID | `VG-0438` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/forms/fields/files.py:109`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/forms/fields/files.py#L109). Engine message: `Unchecked_Input_for_Loop_Condition: loads at indico/web/forms/fields/files.py:91 reaches data at indico/web/forms/fields/files.py:109`.

```py
  107          data = self.object_data if isinstance(self.data, dict) else self.data
  108          if self.allow_multiple_files:
  109              return [self.get_metadata(f) for f in data] if data else []
  110          else:
  111              return self.get_metadata(data) if data else None
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/forms/fields/files.py:109` and, if so, apply the standard mitigation for CWE-606.

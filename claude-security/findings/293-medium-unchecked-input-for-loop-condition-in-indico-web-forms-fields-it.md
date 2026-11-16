# Unchecked Input for Loop Condition in indico/web/forms/fields/itemlists.py:139

| Field | Value |
|---|---|
| ID | `VG-0440` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/forms/fields/itemlists.py:139`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/forms/fields/itemlists.py#L139). Engine message: `Unchecked_Input_for_Loop_Condition: loads at indico/web/forms/fields/itemlists.py:129 reaches enumerate at indico/web/forms/fields/itemlists.py:139`.

```py
  137          uuid_used = set()
  138          coercions = {f['id']: f['coerce'] for f in self.fields if f.get('coerce') is not None}
  139          for i, item in enumerate(self.serialized_data):
  140              if not isinstance(item, dict):
  141                  raise ValidationError(f'Invalid item type: {type(item).__name__}')
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/forms/fields/itemlists.py:139` and, if so, apply the standard mitigation for CWE-606.

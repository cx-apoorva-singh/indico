# Unchecked Input for Loop Condition in indico/web/forms/fields/itemlists.py:131

| Field | Value |
|---|---|
| ID | `VG-0439` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/web/forms/fields/itemlists.py:131`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/forms/fields/itemlists.py#L131). Engine message: `Unchecked_Input_for_Loop_Condition: loads at indico/web/forms/fields/itemlists.py:127 reaches data at indico/web/forms/fields/itemlists.py:131`.

```py
  129              self.serialized_data = json.loads(valuelist[0])
  130              if self.uuid_field and not self.uuid_field_opaque:
  131                  for item in self.data:
  132                      if self.uuid_field not in item:
  133                          item[self.uuid_field] = str(uuid.uuid4())
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/forms/fields/itemlists.py:131` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/events/abstracts/util.py:428

| Field | Value |
|---|---|
| ID | `VG-0242` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/abstracts/util.py:428`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/util.py#L428). Engine message: `Unchecked_Input_for_Loop_Condition: field_values at indico/modules/events/abstracts/views.py:55 reaches fields at indico/modules/events/abstracts/util.py:428`.

```py
  426  
  427  def filter_field_values(fields, can_manage, owns_abstract):
  428      active_fields = {field for field in fields if field.contribution_field.is_active}
  429      if can_manage:
  430          return active_fields
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/util.py:428` and, if so, apply the standard mitigation for CWE-606.

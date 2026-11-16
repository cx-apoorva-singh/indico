# Unchecked Input for Loop Condition in indico/modules/events/contributions/controllers/management.py:750

| Field | Value |
|---|---|
| ID | `VG-0256` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/contributions/controllers/management.py:750`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/controllers/management.py#L750). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/contributions/controllers/management.py:749 reaches enumerate at indico/modules/events/contributions/controllers/management.py:750`.

```py
  748          field_by_id = {field.id: field for field in self.event.contribution_fields}
  749          field_ids = request.form.getlist('field_ids', type=int)
  750          for index, field_id in enumerate(field_ids, 0):
  751              field_by_id[field_id].position = index
  752              del field_by_id[field_id]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/controllers/management.py:750` and, if so, apply the standard mitigation for CWE-606.

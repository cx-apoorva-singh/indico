# Unchecked Input for Loop Condition in indico/modules/events/registration/tasks.py:39

| Field | Value |
|---|---|
| ID | `VG-0311` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/tasks.py:39`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/tasks.py#L39). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/tasks.py:55 reaches registration_data at indico/modules/events/registration/tasks.py:39`.

```py
   37  def _group_by_regform(registration_data):
   38      data_by_regform = defaultdict(list)
   39      for data in registration_data:
   40          data_by_regform[data.field_data.field.registration_form].append(data)
   41      return data_by_regform
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/tasks.py:39` and, if so, apply the standard mitigation for CWE-606.

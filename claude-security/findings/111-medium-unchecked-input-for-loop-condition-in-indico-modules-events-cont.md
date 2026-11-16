# Unchecked Input for Loop Condition in indico/modules/events/contributions/lists.py:95

| Field | Value |
|---|---|
| ID | `VG-0258` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/contributions/lists.py:95`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/lists.py#L95). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/contributions/lists.py:95 reaches getlist at indico/modules/events/contributions/lists.py:95`.

```py
   93          for field in self.event.contribution_fields:
   94              if field.field_type == 'single_choice':
   95                  options = [x if x != 'None' else None for x in request.form.getlist(f'field_{field.id}')]
   96                  if options:
   97                      filters['fields'][str(field.id)] = options
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/lists.py:95` and, if so, apply the standard mitigation for CWE-606.

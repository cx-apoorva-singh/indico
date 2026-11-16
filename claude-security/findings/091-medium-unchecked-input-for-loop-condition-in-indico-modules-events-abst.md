# Unchecked Input for Loop Condition in indico/modules/events/abstracts/lists.py:90

| Field | Value |
|---|---|
| ID | `VG-0238` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/abstracts/lists.py:90`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/lists.py#L90). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/abstracts/lists.py:90 reaches getlist at indico/modules/events/abstracts/lists.py:90`.

```py
   88          for field in self.event.contribution_fields:
   89              if field.field_type == 'single_choice':
   90                  options = [x if x != 'None' else None for x in request.form.getlist(f'field_{field.id}')]
   91                  if options:
   92                      filters['fields'][str(field.id)] = options
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/lists.py:90` and, if so, apply the standard mitigation for CWE-606.

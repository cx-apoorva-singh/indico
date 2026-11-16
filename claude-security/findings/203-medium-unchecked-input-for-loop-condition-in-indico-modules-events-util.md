# Unchecked Input for Loop Condition in indico/modules/events/util.py:319

| Field | Value |
|---|---|
| ID | `VG-0350` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/util.py:319`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/util.py#L319). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/util.py:319 reaches getlist at indico/modules/events/util.py:319`.

```py
  317          def get_selected_options(item_id, item):
  318              if _get(item, 'filter_choices') or _get('type', 'bool'):
  319                  return [x if x != 'None' else None for x in request.form.getlist(f'field_{item_id}')]
  320  
  321          filters = deepcopy(self.default_list_config['filters'])
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/util.py:319` and, if so, apply the standard mitigation for CWE-606.

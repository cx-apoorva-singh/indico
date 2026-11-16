# Unchecked Input for Loop Condition in indico/modules/events/registration/forms.py:407

| Field | Value |
|---|---|
| ID | `VG-0307` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/forms.py:407`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/forms.py#L407). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/designer/util.py:150 reaches all_templates at indico/modules/events/registration/forms.py:407`.

```py
  405          event_templates = get_printable_event_templates(regform)
  406          all_templates = set(event_templates) | get_inherited_templates(event)
  407          badge_templates = [(tpl.id, tpl.title) for tpl in all_templates
  408                             if tpl.type == TemplateType.badge and tpl != default_tpl]
  409          # Show the default template first
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/forms.py:407` and, if so, apply the standard mitigation for CWE-606.

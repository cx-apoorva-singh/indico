# Unchecked Input for Loop Condition in indico/modules/designer/controllers.py:506

| Field | Value |
|---|---|
| ID | `VG-0230` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/designer/controllers.py:506`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/designer/controllers.py#L506). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/designer/controllers.py:505 reaches system_templates at indico/modules/designer/controllers.py:506`.

```py
  504              system_templates = DesignerTemplate.query.filter(DesignerTemplate.is_system_template,
  505                                                               DesignerTemplate.type == TemplateType.badge).all()
  506              system_template = next(tpl for tpl in system_templates if tpl.is_ticket)
  507              root.default_ticket_template = system_template
  508          if not root.default_badge_template:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/designer/controllers.py:506` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/designer/controllers.py:333

| Field | Value |
|---|---|
| ID | `VG-0229` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/designer/controllers.py:333`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/designer/controllers.py#L333). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/designer/controllers.py:331 reaches backside_templates at indico/modules/designer/controllers.py:333`.

```py
  331                                .all())
  332          related_tpls_per_owner = defaultdict(list)
  333          for bs_tpl in backside_templates:
  334              related_tpls_per_owner[bs_tpl.owner].append(bs_tpl)
  335          placeholders = get_nested_placeholder_options(regform=self.template.registration_form)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/designer/controllers.py:333` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/events/abstracts/controllers/email_templates.py:53

| Field | Value |
|---|---|
| ID | `VG-0234` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/abstracts/controllers/email_templates.py:53`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/controllers/email_templates.py#L53). Engine message: `Unchecked_Input_for_Loop_Condition: json at indico/modules/events/abstracts/controllers/email_templates.py:51 reaches enumerate at indico/modules/events/abstracts/controllers/email_templates.py:53`.

```py
   51          sort_order = request.json['sort_order']
   52          tpls = {s.id: s for s in self.event.abstract_email_templates}
   53          for position, tpl_id in enumerate(sort_order, 1):
   54              if tpl_id in tpls:
   55                  tpls[tpl_id].position = position
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/controllers/email_templates.py:53` and, if so, apply the standard mitigation for CWE-606.

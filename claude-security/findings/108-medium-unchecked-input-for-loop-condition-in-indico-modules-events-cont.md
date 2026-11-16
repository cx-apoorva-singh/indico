# Unchecked Input for Loop Condition in indico/modules/events/contributions/controllers/management.py:451

| Field | Value |
|---|---|
| ID | `VG-0255` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/contributions/controllers/management.py:451`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/controllers/management.py#L451). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/contributions/controllers/management.py:449 reaches enumerate at indico/modules/events/contributions/controllers/management.py:451`.

```py
  449          subcontrib_ids = request.form.getlist('subcontrib_ids', type=int)
  450          subcontribs = {s.id: s for s in self.contrib.subcontributions}
  451          for position, subcontrib_id in enumerate(subcontrib_ids, 1):
  452              if subcontrib_id in subcontribs:
  453                  subcontribs[subcontrib_id].position = position
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/controllers/management.py:451` and, if so, apply the standard mitigation for CWE-606.

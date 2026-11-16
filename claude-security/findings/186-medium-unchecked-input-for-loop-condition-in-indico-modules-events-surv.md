# Unchecked Input for Loop Condition in indico/modules/events/surveys/controllers/management/questionnaire.py:340

| Field | Value |
|---|---|
| ID | `VG-0333` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/surveys/controllers/management/questionnaire.py:340`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/surveys/controllers/management/questionnaire.py#L340). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/surveys/controllers/management/questionnaire.py:338 reaches enumerate at indico/modules/events/surveys/controllers/management/questionnaire.py:340`.

```py
  338          item_ids = request.form.getlist('item_ids', type=int)
  339          changed_section = None
  340          for position, item_id in enumerate(item_ids, 1):
  341              try:
  342                  section_items[item_id].position = position
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/surveys/controllers/management/questionnaire.py:340` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/events/surveys/controllers/management/questionnaire.py:328

| Field | Value |
|---|---|
| ID | `VG-0332` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/surveys/controllers/management/questionnaire.py:328`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/surveys/controllers/management/questionnaire.py#L328). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/surveys/controllers/management/questionnaire.py:327 reaches enumerate at indico/modules/events/surveys/controllers/management/questionnaire.py:328`.

```py
  326          sections = {section.id: section for section in self.survey.sections}
  327          section_ids = request.form.getlist('section_ids', type=int)
  328          for position, section_id in enumerate(section_ids, 1):
  329              sections[section_id].position = position
  330          logger.info('Sections in %s reordered by %s', self.survey, session.user)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/surveys/controllers/management/questionnaire.py:328` and, if so, apply the standard mitigation for CWE-606.

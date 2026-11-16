# Unchecked Input for Loop Condition in indico/modules/events/surveys/controllers/display.py:146

| Field | Value |
|---|---|
| ID | `VG-0331` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/surveys/controllers/display.py:146`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/surveys/controllers/display.py#L146). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/surveys/controllers/display.py:146 reaches lists at indico/modules/events/surveys/controllers/display.py:146`.

```py
  144  
  145      def _process(self):
  146          pending_answers = {k: v for k, v in request.form.lists() if k.startswith('question_')}
  147          if not self.submission:
  148              self.submission = SurveySubmission(survey=self.survey, user=session.user)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/surveys/controllers/display.py:146` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/events/surveys/tasks.py:22

| Field | Value |
|---|---|
| ID | `VG-0336` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/surveys/tasks.py:22`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/surveys/tasks.py#L22). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/surveys/tasks.py:21 reaches active_surveys at indico/modules/events/surveys/tasks.py:22`.

```py
   20                                Survey.notifications_enabled)
   21                        .all())
   22      for survey in active_surveys:
   23          survey.send_start_notification()
   24      db.session.commit()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/surveys/tasks.py:22` and, if so, apply the standard mitigation for CWE-606.

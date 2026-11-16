# Unchecked Input for Loop Condition in indico/modules/events/reminders/tasks.py:28

| Field | Value |
|---|---|
| ID | `VG-0326` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/reminders/tasks.py:28`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/reminders/tasks.py#L28). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/reminders/tasks.py:27 reaches reminders at indico/modules/events/reminders/tasks.py:28`.

```py
   26                   .join(EventReminder.event)
   27                   .all())
   28      for reminder in reminders:
   29          logger.info('Sending event reminder: %s', reminder)
   30          reminder.send()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/reminders/tasks.py:28` and, if so, apply the standard mitigation for CWE-606.

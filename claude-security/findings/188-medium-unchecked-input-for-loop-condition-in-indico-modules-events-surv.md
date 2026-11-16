# Unchecked Input for Loop Condition in indico/modules/events/surveys/models/surveys.py:253

| Field | Value |
|---|---|
| ID | `VG-0335` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/surveys/models/surveys.py:253`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/surveys/models/surveys.py#L253). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/models/registrations.py:331 reaches get_all_for_event at indico/modules/events/surveys/models/surveys.py:253`.

```py
  251          recipients = set(self.start_notification_emails)
  252          if self.notify_participants:
  253              recipients.update(reg.email for reg in Registration.get_all_for_event(self.event))
  254          recipients.discard('')  # just in case there was an empty email address somewhere
  255          return recipients
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/surveys/models/surveys.py:253` and, if so, apply the standard mitigation for CWE-606.

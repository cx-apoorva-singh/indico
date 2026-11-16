# Unchecked Input for Loop Condition in indico/modules/events/surveys/controllers/management/survey.py:199

| Field | Value |
|---|---|
| ID | `VG-0334` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/surveys/controllers/management/survey.py:199`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/surveys/controllers/management/survey.py#L199). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/models/registrations.py:331 reaches registrations at indico/modules/events/surveys/controllers/management/survey.py:199`.

```py
  197          if email_all_participants:
  198              registrations = Registration.get_all_for_event(self.event)
  199              self.recipients |= {r.email for r in registrations}
  200          if recipients_addresses:
  201              self.recipients |= set(recipients_addresses)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/surveys/controllers/management/survey.py:199` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/events/reminders/models/reminders.py:256

| Field | Value |
|---|---|
| ID | `VG-0323` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/reminders/models/reminders.py:256`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/reminders/models/reminders.py#L256). Engine message: `Unchecked_Input_for_Loop_Condition: having at indico/modules/events/reminders/models/reminders.py:250 reaches regs_query at indico/modules/events/reminders/models/reminders.py:256`.

```py
  254                  regs_query = regs_query.filter(Registration.id.in_(tags_query))
  255  
  256              recipients.update(reg.email for reg in regs_query)
  257  
  258          if self.send_to_speakers:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/reminders/models/reminders.py:256` and, if so, apply the standard mitigation for CWE-606.

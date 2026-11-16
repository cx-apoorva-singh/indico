# Unchecked Input for Loop Condition in indico/modules/events/registration/util.py:955

| Field | Value |
|---|---|
| ID | `VG-0321` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/util.py:955`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/util.py#L955). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/registration/util.py:954 reaches reg_data at indico/modules/events/registration/util.py:955`.

```py
  953                  .filter(Registration.is_active)
  954                  .all())
  955      registered_user_ids = {rd.user_id for rd in reg_data if rd.user_id is not None}
  956      registered_emails = {rd.email for rd in reg_data}
  957      invited_emails = {inv.email for inv in regform.invitations}
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/util.py:955` and, if so, apply the standard mitigation for CWE-606.

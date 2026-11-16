# Unchecked Input for Loop Condition in indico/modules/events/registration/controllers/display.py:252

| Field | Value |
|---|---|
| ID | `VG-0297` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/controllers/display.py:252`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/display.py#L252). Engine message: `Unchecked_Input_for_Loop_Condition: signal_query at indico/modules/events/registration/controllers/display.py:251 reaches query at indico/modules/events/registration/controllers/display.py:252`.

```py
  250                             Registration.friendly_id)
  251                   .signal_query('participant-list-publishable-registrations', regform=regform))
  252          registrations = [_process_registration(reg, column_ids, active_fields, picture_ids) for reg in query
  253                           if reg.is_publishable(is_participant)]
  254  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/display.py:252` and, if so, apply the standard mitigation for CWE-606.

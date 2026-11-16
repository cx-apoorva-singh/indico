# Unchecked Input for Loop Condition in indico/modules/events/registration/util.py:699

| Field | Value |
|---|---|
| ID | `VG-0316` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/util.py:699`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/util.py#L699). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/registration/util.py:698 reaches query at indico/modules/events/registration/util.py:699`.

```py
  697      query = (RegistrationForm.query.with_parent(event)
  698               .options(joinedload('registrations').joinedload('data').joinedload('field_data')))
  699      for regform in query:
  700          for registration in regform.active_registrations:
  701              registration_info = _build_base_registration_info(registration)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/util.py:699` and, if so, apply the standard mitigation for CWE-606.

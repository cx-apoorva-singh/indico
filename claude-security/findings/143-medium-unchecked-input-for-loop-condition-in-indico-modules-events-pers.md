# Unchecked Input for Loop Condition in indico/modules/events/persons/controllers.py:212

| Field | Value |
|---|---|
| ID | `VG-0290` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/persons/controllers.py:212`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/persons/controllers.py#L212). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/persons/controllers.py:211 reaches regs at indico/modules/events/persons/controllers.py:212`.

```py
  210                          Registration.is_active, ~RegistrationForm.is_deleted)
  211                  .all())
  212          for reg in regs:
  213              internal_role_users[reg.user.email]['registrations'].append(reg)
  214  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/persons/controllers.py:212` and, if so, apply the standard mitigation for CWE-606.

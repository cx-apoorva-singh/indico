# Unchecked Input for Loop Condition in indico/modules/rb/notifications/reservations.py:39

| Field | Value |
|---|---|
| ID | `VG-0384` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/notifications/reservations.py:39`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/notifications/reservations.py#L39). Engine message: `Unchecked_Input_for_Loop_Condition: filter at indico/modules/rb/notifications/reservations.py:37 reaches query at indico/modules/rb/notifications/reservations.py:39`.

```py
   37               .filter(UserSetting.module == 'roombooking',
   38                       email_mode_filter | room_blacklist_filter))
   39      disabled_emails = {u.email for u in query}
   40      if include_moderators:
   41          manager_emails = room.get_manager_emails(permission='moderate')  # this includes full managers
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/notifications/reservations.py:39` and, if so, apply the standard mitigation for CWE-606.

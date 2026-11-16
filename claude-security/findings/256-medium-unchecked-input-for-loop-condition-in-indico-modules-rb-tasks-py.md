# Unchecked Input for Loop Condition in indico/modules/rb/tasks.py:166

| Field | Value |
|---|---|
| ID | `VG-0403` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/tasks.py:166`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/tasks.py#L166). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/tasks.py:164 reaches groupby at indico/modules/rb/tasks.py:166`.

```py
  164                      .all())
  165  
  166      for user, user_reservations in groupby(reservations, key=attrgetter('booked_for_user')):
  167          user_reservations = list(user_reservations)
  168          notify_about_finishing_bookings(user, list(user_reservations))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/tasks.py:166` and, if so, apply the standard mitigation for CWE-606.

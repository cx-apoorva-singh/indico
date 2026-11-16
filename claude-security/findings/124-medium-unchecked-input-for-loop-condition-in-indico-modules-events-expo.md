# Unchecked Input for Loop Condition in indico/modules/events/export.py:898

| Field | Value |
|---|---|
| ID | `VG-0271` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/export.py:898`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/export.py#L898). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/events/export.py:897 reaches query at indico/modules/events/export.py:898`.

```py
  896                   .filter(Registration.user_id.is_(None))
  897                   .order_by(Registration.is_deleted))
  898          for registration in query:
  899              if not (user := get_user_by_email(registration.email)):
  900                  continue
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/export.py:898` and, if so, apply the standard mitigation for CWE-606.

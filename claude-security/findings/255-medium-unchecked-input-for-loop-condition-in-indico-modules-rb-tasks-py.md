# Unchecked Input for Loop Condition in indico/modules/rb/tasks.py:112

| Field | Value |
|---|---|
| ID | `VG-0402` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/tasks.py:112`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/tasks.py#L112). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/tasks.py:110 reaches groupby at indico/modules/rb/tasks.py:112`.

```py
  110                     .all())
  111  
  112      for user, user_occurrences in groupby(occurrences, key=attrgetter('reservation.booked_for_user')):
  113          user_occurrences = list(user_occurrences)
  114          if debug:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/tasks.py:112` and, if so, apply the standard mitigation for CWE-606.

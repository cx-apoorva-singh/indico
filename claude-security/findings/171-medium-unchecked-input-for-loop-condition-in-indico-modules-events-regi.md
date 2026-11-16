# Unchecked Input for Loop Condition in indico/modules/events/registration/util.py:863

| Field | Value |
|---|---|
| ID | `VG-0318` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/util.py:863`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/util.py#L863). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/events/registration/util.py:834 reaches all_regforms at indico/modules/events/registration/util.py:863`.

```py
  861                                if (regform.is_scheduled and not regform.private) or registration]
  862      else:
  863          displayed_regforms = [regform for regform, registration in all_regforms
  864                                if (regform.is_open and not regform.private) or registration]
  865      return displayed_regforms, dict(all_regforms)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/util.py:863` and, if so, apply the standard mitigation for CWE-606.

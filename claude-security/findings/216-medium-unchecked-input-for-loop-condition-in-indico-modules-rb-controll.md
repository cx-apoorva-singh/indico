# Unchecked Input for Loop Condition in indico/modules/rb/controllers/backend/bookings.py:81

| Field | Value |
|---|---|
| ID | `VG-0363` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/controllers/backend/bookings.py:81`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/controllers/backend/bookings.py#L81). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/controllers/backend/bookings.py:77 reaches values at indico/modules/rb/controllers/backend/bookings.py:81`.

```py
   79          date_range = [dt.isoformat() for dt in date_range]
   80  
   81          for data in availability.values():
   82              # add additional helpful attributes
   83              data.update({
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/controllers/backend/bookings.py:81` and, if so, apply the standard mitigation for CWE-606.

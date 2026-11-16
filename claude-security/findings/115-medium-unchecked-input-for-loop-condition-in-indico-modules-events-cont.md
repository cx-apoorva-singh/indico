# Unchecked Input for Loop Condition in indico/modules/events/contributions/util.py:294

| Field | Value |
|---|---|
| ID | `VG-0262` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/contributions/util.py:294`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/util.py#L294). Engine message: `Unchecked_Input_for_Loop_Condition: reader at indico/modules/events/contributions/util.py:291 reaches enumerate at indico/modules/events/contributions/util.py:294`.

```py
  292  
  293      contrib_data = []
  294      for num_row, row in enumerate(reader, 1):
  295          try:
  296              start_dt, duration, title, first_name, last_name, affiliation, email = (value.strip() for value in row)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/util.py:294` and, if so, apply the standard mitigation for CWE-606.

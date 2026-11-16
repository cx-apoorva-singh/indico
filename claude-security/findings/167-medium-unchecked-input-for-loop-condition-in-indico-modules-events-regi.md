# Unchecked Input for Loop Condition in indico/modules/events/registration/util.py:93

| Field | Value |
|---|---|
| ID | `VG-0314` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/registration/util.py:93`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/util.py#L93). Engine message: `Unchecked_Input_for_Loop_Condition: reader at indico/modules/events/registration/util.py:89 reaches enumerate at indico/modules/events/registration/util.py:93`.

```py
   91      email_row_map = {}
   92      user_records = []
   93      for row_num, row in enumerate(reader, 1):
   94          values = [value.strip() for value in row]
   95          if len(columns) != len(values):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/util.py:93` and, if so, apply the standard mitigation for CWE-606.

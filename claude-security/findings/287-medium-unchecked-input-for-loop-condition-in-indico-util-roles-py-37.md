# Unchecked Input for Loop Condition in indico/util/roles.py:37

| Field | Value |
|---|---|
| ID | `VG-0434` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/util/roles.py:37`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/util/roles.py#L37). Engine message: `Unchecked_Input_for_Loop_Condition: reader at indico/util/roles.py:34 reaches enumerate at indico/util/roles.py:37`.

```py
   35  
   36          emails = set()
   37          for num_row, row in enumerate(reader, 1):
   38              if len(row) != 1:
   39                  raise UserValueError(_('Row {}: malformed CSV data').format(num_row))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/util/roles.py:37` and, if so, apply the standard mitigation for CWE-606.

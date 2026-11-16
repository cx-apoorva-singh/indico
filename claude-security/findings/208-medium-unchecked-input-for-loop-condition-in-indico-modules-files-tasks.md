# Unchecked Input for Loop Condition in indico/modules/files/tasks.py:31

| Field | Value |
|---|---|
| ID | `VG-0355` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/files/tasks.py:31`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/files/tasks.py#L31). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/files/tasks.py:29 reaches unclaimed_files at indico/modules/files/tasks.py:31`.

```py
   29                         .all())
   30  
   31      for file in unclaimed_files:
   32          file_repr = repr(file)
   33          if config.DEBUG:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/files/tasks.py:31` and, if so, apply the standard mitigation for CWE-606.

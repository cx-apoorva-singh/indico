# Unchecked Input for Loop Condition in indico/modules/users/export.py:145

| Field | Value |
|---|---|
| ID | `VG-0415` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/users/export.py:145`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/export.py#L145). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/users/export.py:259 reaches get_abstracts at indico/modules/users/export.py:145`.

```py
  143  
  144      if DataExportOptions.abstracts_papers in options:
  145          for abstract in get_abstracts(user):
  146              yield from abstract.files
  147  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/export.py:145` and, if so, apply the standard mitigation for CWE-606.

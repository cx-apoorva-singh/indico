# Unchecked Input for Loop Condition in indico/modules/users/export.py:141

| Field | Value |
|---|---|
| ID | `VG-0414` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/users/export.py:141`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/export.py#L141). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/users/export.py:199 reaches get_attachments at indico/modules/users/export.py:141`.

```py
  139  
  140      if DataExportOptions.attachments in options:
  141          for attachment in get_attachments(user):
  142              yield attachment.file
  143  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/export.py:141` and, if so, apply the standard mitigation for CWE-606.

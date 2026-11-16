# Unchecked Input for Loop Condition in indico/modules/users/tasks.py:68

| Field | Value |
|---|---|
| ID | `VG-0424` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/users/tasks.py:68`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/tasks.py#L68). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/users/export.py:383 reaches old_requests at indico/modules/users/tasks.py:68`.

```py
   66  
   67      logger.info('Marking for deletion %d expired user data exports from the past %d days', len(old_requests), days)
   68      for request in old_requests:
   69          request.state = DataExportRequestState.expired
   70          if request.file:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/tasks.py:68` and, if so, apply the standard mitigation for CWE-606.

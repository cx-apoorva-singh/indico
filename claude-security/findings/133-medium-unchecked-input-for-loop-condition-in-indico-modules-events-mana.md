# Unchecked Input for Loop Condition in indico/modules/events/management/util.py:136

| Field | Value |
|---|---|
| ID | `VG-0280` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/management/util.py:136`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/management/util.py#L136). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/management/util.py:83 reaches _process_attachments at indico/modules/events/management/util.py:136`.

```py
  134              )
  135          )
  136          for obj in _process_attachments(_query_folders(root, crit)):
  137              yield _ProtectedObjectWrapper(obj)
  138          for contrib in root.contributions:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/management/util.py:136` and, if so, apply the standard mitigation for CWE-606.

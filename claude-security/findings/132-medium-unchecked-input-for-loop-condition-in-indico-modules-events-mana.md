# Unchecked Input for Loop Condition in indico/modules/events/management/util.py:86

| Field | Value |
|---|---|
| ID | `VG-0279` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/management/util.py:86`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/management/util.py#L86). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/management/util.py:83 reaches folders at indico/modules/events/management/util.py:86`.

```py
   84  
   85      def _process_attachments(folders):
   86          for folder in folders:
   87              if not folder.is_inheriting:
   88                  yield folder
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/management/util.py:86` and, if so, apply the standard mitigation for CWE-606.

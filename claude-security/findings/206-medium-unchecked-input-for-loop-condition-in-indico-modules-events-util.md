# Unchecked Input for Loop Condition in indico/modules/events/util.py:711

| Field | Value |
|---|---|
| ID | `VG-0353` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/util.py:711`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/util.py#L711). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/attachments/tasks.py:20 reaches files_holder at indico/modules/events/util.py:711`.

```py
  709  
  710      def _iter_items(self, files_holder):
  711          yield from files_holder
  712  
  713      def _get_item_path(self, item):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/util.py:711` and, if so, apply the standard mitigation for CWE-606.

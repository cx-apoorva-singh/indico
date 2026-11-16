# Unchecked Input for Loop Condition in indico/modules/events/editing/clone.py:55

| Field | Value |
|---|---|
| ID | `VG-0265` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/editing/clone.py:55`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/editing/clone.py#L55). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/editing/clone.py:54 reaches old_conditions at indico/modules/events/editing/clone.py:55`.

```py
   53      def _clone_review_conditions(self, new_event):
   54          old_conditions = EditingReviewCondition.query.with_parent(self.old_event).all()
   55          for condition in old_conditions:
   56              new_filetypes = {self._filetype_map[ft] for ft in condition.file_types}
   57              new_condition = EditingReviewCondition(type=condition.type, file_types=new_filetypes)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/editing/clone.py:55` and, if so, apply the standard mitigation for CWE-606.

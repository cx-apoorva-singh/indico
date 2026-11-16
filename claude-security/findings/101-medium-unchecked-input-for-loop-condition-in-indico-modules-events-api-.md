# Unchecked Input for Loop Condition in indico/modules/events/api.py:565

| Field | Value |
|---|---|
| ID | `VG-0248` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/api.py:565`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/api.py#L565). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/api.py:588 reaches chain at indico/modules/events/api.py:565`.

```py
  563      def _serialize_category_path(self, category):
  564          visibility = {'id': None, 'name': 'Everywhere'}
  565          path = [self._serialize_path_entry(category_data) for category_data in category.chain]
  566          if category.visibility is not None:
  567              try:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/api.py:565` and, if so, apply the standard mitigation for CWE-606.

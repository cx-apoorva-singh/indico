# Unchecked Input for Loop Condition in indico/modules/events/management/controllers/protection.py:150

| Field | Value |
|---|---|
| ID | `VG-0278` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/management/controllers/protection.py:150`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/management/controllers/protection.py#L150). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/categories/models/roles.py:114 reaches category_roles at indico/modules/events/management/controllers/protection.py:150`.

```py
  148      def _process(self):
  149          category_roles = CategoryRole.get_category_roles(self.event.category)
  150          return jsonify([serialize_category_role(cr, legacy=False) for cr in category_roles])
  151  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/management/controllers/protection.py:150` and, if so, apply the standard mitigation for CWE-606.

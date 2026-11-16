# Unchecked Input for Loop Condition in indico/modules/events/editing/schemas.py:427

| Field | Value |
|---|---|
| ID | `VG-0268` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/editing/schemas.py:427`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/editing/schemas.py#L427). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/editing/schemas.py:426 reaches event_conditions at indico/modules/events/editing/schemas.py:427`.

```py
  425  
  426          event_conditions = EditingReviewCondition.query.with_parent(event).filter_by(type=editable_type).all()
  427          if any(condition_types == {ft.id for ft in cond.file_types} for cond in event_conditions):
  428              raise ValidationError(_('Conditions have to be unique'))
  429  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/editing/schemas.py:427` and, if so, apply the standard mitigation for CWE-606.

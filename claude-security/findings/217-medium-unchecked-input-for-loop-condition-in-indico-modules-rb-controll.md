# Unchecked Input for Loop Condition in indico/modules/rb/controllers/backend/misc.py:137

| Field | Value |
|---|---|
| ID | `VG-0364` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/controllers/backend/misc.py:137`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/controllers/backend/misc.py#L137). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/controllers/backend/misc.py:136 reaches res at indico/modules/rb/controllers/backend/misc.py:137`.

```py
  135                 .order_by(EquipmentType.name)
  136                 .all())
  137          used_ids = {eq.id for eq, used in res if used}
  138          schema = EquipmentTypeSchema(many=True, context={'used_ids': used_ids})
  139          return schema.dump(eq for eq, __ in res)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/controllers/backend/misc.py:137` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/events/contributions/controllers/management.py:753

| Field | Value |
|---|---|
| ID | `VG-0257` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/contributions/controllers/management.py:753`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/controllers/management.py#L753). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/contributions/controllers/management.py:749 reaches enumerate at indico/modules/events/contributions/controllers/management.py:753`.

```py
  751              field_by_id[field_id].position = index
  752              del field_by_id[field_id]
  753          for index, field in enumerate(sorted(field_by_id.values(), key=attrgetter('position')), len(field_ids)):
  754              field.position = index
  755          db.session.flush()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/controllers/management.py:753` and, if so, apply the standard mitigation for CWE-606.

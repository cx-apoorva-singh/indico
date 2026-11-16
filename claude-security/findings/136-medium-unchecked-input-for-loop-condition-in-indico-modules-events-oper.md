# Unchecked Input for Loop Condition in indico/modules/events/operations.py:359

| Field | Value |
|---|---|
| ID | `VG-0283` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/operations.py:359`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/operations.py#L359). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/abstracts/controllers/management.py:286 reaches enumerate at indico/modules/events/operations.py:359`.

```py
  357          questions_by_id[new_position].position = index
  358          del questions_by_id[new_position]
  359      for index, field in enumerate(sorted(questions_by_id.values(), key=attrgetter('position')), len(new_positions)):
  360          field.position = index
  361      db.session.flush()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/operations.py:359` and, if so, apply the standard mitigation for CWE-606.

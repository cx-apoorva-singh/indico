# Unchecked Input for Loop Condition in indico/modules/users/export.py:281

| Field | Value |
|---|---|
| ID | `VG-0422` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/users/export.py:281`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/export.py#L281). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/users/export.py:280 reaches query at indico/modules/users/export.py:281`.

```py
  279                              EditingRevision.user == user))
  280               .all())
  281      editable_ids = {eid for eid, in query}
  282      revisions_strategy = joinedload('revisions')
  283      # revisions_strategy.selectinload('comments').joinedload('user')
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/export.py:281` and, if so, apply the standard mitigation for CWE-606.

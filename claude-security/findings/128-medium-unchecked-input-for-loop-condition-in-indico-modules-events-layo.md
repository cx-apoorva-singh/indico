# Unchecked Input for Loop Condition in indico/modules/events/layout/util.py:204

| Field | Value |
|---|---|
| ID | `VG-0275` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/layout/util.py:204`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/layout/util.py#L204). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/layout/util.py:200 reaches query at indico/modules/events/layout/util.py:204`.

```py
  202                        joinedload('children').load_only('id', 'parent_id', 'name', 'position')))
  203  
  204      existing = {entry.name: entry for entry in query}
  205      pos_gen = count(start=(max(x.position for x in existing.values() if not x.parent) + 1))
  206      entries = []
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/layout/util.py:204` and, if so, apply the standard mitigation for CWE-606.

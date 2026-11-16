# Unchecked Input for Loop Condition in indico/modules/search/internal.py:240

| Field | Value |
|---|---|
| ID | `VG-0410` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/search/internal.py:240`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/search/internal.py#L240). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/search/internal.py:233 reaches query at indico/modules/search/internal.py:240`.

```py
  238              )
  239          )
  240          events_by_id = {e.id: e for e in query}
  241          events = [events_by_id[e.id] for e in objs]
  242  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/search/internal.py:240` and, if so, apply the standard mitigation for CWE-606.

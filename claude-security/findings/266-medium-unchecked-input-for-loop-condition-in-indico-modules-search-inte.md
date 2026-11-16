# Unchecked Input for Loop Condition in indico/modules/search/internal.py:554

| Field | Value |
|---|---|
| ID | `VG-0413` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/search/internal.py:554`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/search/internal.py#L554). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/search/internal.py:547 reaches query at indico/modules/search/internal.py:554`.

```py
  552              )
  553          )
  554          notes_by_id = {n.id: n for n in query}
  555          notes = [notes_by_id[n.id] for n in objs]
  556  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/search/internal.py:554` and, if so, apply the standard mitigation for CWE-606.

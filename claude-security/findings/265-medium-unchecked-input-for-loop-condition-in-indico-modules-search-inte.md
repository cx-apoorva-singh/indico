# Unchecked Input for Loop Condition in indico/modules/search/internal.py:437

| Field | Value |
|---|---|
| ID | `VG-0412` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/search/internal.py:437`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/search/internal.py#L437). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/search/internal.py:428 reaches query at indico/modules/search/internal.py:437`.

```py
  435              )
  436          )
  437          attachments_by_id = {a.id: a for a in query}
  438          attachments = [attachments_by_id[a.id] for a in objs]
  439  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/search/internal.py:437` and, if so, apply the standard mitigation for CWE-606.

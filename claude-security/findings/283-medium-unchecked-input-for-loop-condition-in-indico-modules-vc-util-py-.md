# Unchecked Input for Loop Condition in indico/modules/vc/util.py:62

| Field | Value |
|---|---|
| ID | `VG-0430` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/vc/util.py:62`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/vc/util.py#L62). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/vc/util.py:54 reaches query at indico/modules/vc/util.py:62`.

```py
   60          if to_dt is not None:
   61              query = query.filter(Event.start_dt < to_dt)
   62      yield from query
   63  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/vc/util.py:62` and, if so, apply the standard mitigation for CWE-606.

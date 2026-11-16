# Unchecked Input for Loop Condition in indico/util/console.py:87

| Field | Value |
|---|---|
| ID | `VG-0431` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/util/console.py:87`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/util/console.py#L87). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/export.py:844 reaches enumerate at indico/util/console.py:87`.

```py
   85          sys.stdout.flush()
   86  
   87      for i, item in enumerate(iterable, 1):
   88          if i % print_every == 0 or i == total:
   89              remaining_seconds = int((time.time() - start_time) / i * (total - i))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/util/console.py:87` and, if so, apply the standard mitigation for CWE-606.

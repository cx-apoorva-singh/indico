# Unchecked Input for Loop Condition in bin/utils/storage_checksums.py:40

| Field | Value |
|---|---|
| ID | `VG-0205` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`bin/utils/storage_checksums.py:40`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/utils/storage_checksums.py#L40). Engine message: `Unchecked_Input_for_Loop_Condition: options at bin/utils/storage_checksums.py:32 reaches limit at bin/utils/storage_checksums.py:40`.

```py
   38      while True:
   39          row = None
   40          for row in query.limit(chunk_size):
   41              yield row
   42          db.session.commit()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/utils/storage_checksums.py:40` and, if so, apply the standard mitigation for CWE-606.

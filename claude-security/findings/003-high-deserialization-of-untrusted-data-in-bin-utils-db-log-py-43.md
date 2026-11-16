# Deserialization of Untrusted Data in bin/utils/db_log.py:43

| Field | Value |
|---|---|
| ID | `VG-0045` |
| Severity | **High** |
| Status | open |
| CWE | CWE-502 |
| Rule | `Python_Deserialization_of_Untrusted_Data` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Deserialization_of_Untrusted_Data` (CWE-502) reports an issue at [`bin/utils/db_log.py:43`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/utils/db_log.py#L43). Engine message: `Deserialization_of_Untrusted_Data: recv at bin/utils/db_log.py:40 reaches loads at bin/utils/db_log.py:43`.

```py
   41              while len(chunk) < size:
   42                  chunk += self.connection.recv(size - len(chunk))
   43              obj = pickle.loads(chunk)  # noqa: S301
   44              self.handle_log(obj)
   45  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/utils/db_log.py:43` and, if so, apply the standard mitigation for CWE-502.

# Use of Broken or Risky Cryptographic Algorithm in indico/modules/events/agreements/base.py:44

| Field | Value |
|---|---|
| ID | `VG-0453` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`indico/modules/events/agreements/base.py:44`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/agreements/base.py#L44). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
   42              data_string = '-'.join(f'{k}={make_hashable(v)}' for k, v in sorted(self.data.items()))
   43          identifier = f'{self.email}:{data_string or None}'
   44          return sha1(identifier.encode()).hexdigest()
   45  
   46  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/agreements/base.py:44` and, if so, apply the standard mitigation for CWE-327.

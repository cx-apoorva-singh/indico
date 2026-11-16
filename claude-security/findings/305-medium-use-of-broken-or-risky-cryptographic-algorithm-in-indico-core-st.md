# Use of Broken or Risky Cryptographic Algorithm in indico/core/storage/backend.py:109

| Field | Value |
|---|---|
| ID | `VG-0452` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`indico/core/storage/backend.py:109`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/storage/backend.py#L109). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
  107              target.write(chunk)
  108              checksum.update(chunk)
  109          return checksum.hexdigest()
  110  
  111      def open(self, file_id):  # pragma: no cover
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/storage/backend.py:109` and, if so, apply the standard mitigation for CWE-327.

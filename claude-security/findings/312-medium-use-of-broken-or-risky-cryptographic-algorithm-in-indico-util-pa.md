# Use of Broken or Risky Cryptographic Algorithm in indico/util/passwords.py:147

| Field | Value |
|---|---|
| ID | `VG-0459` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`indico/util/passwords.py:147`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/util/passwords.py#L147). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
  145      """
  146      timeout = 1 if fast else 3
  147      sha = hashlib.sha1(password.encode()).hexdigest().upper()
  148      hashes = _get_pwned_hashes(sha[:5], timeout)
  149      if hashes is None:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/util/passwords.py:147` and, if so, apply the standard mitigation for CWE-327.

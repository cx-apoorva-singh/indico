# Use of Broken or Risky Cryptographic Algorithm in indico/modules/users/util.py:520

| Field | Value |
|---|---|
| ID | `VG-0458` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`indico/modules/users/util.py:520`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/util.py#L520). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
  518  
  519  def get_gravatar_for_user(user, identicon, size=256, lastmod=None):
  520      gravatar_url = f'https://www.gravatar.com/avatar/{hashlib.md5(user.email.lower().encode()).hexdigest()}'
  521      if identicon:
  522          params = {'d': 'identicon', 's': str(size), 'forcedefault': 'y'}
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/util.py:520` and, if so, apply the standard mitigation for CWE-327.

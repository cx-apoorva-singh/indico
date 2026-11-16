# Use of Broken or Risky Cryptographic Algorithm in bin/utils/apiProxy.py:34

| Field | Value |
|---|---|
| ID | `VG-0451` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`bin/utils/apiProxy.py:34`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/utils/apiProxy.py#L34). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
   32          items = sorted(items, key=lambda x: x[0].lower())
   33          url = f'{path}?{urlencode(items)}'
   34          signature = hmac.new(secret_key.encode(), url.encode(), hashlib.sha1).hexdigest()
   35          items.append(('signature', signature))
   36      return items
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/utils/apiProxy.py:34` and, if so, apply the standard mitigation for CWE-327.

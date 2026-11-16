# Use of Broken or Risky Cryptographic Algorithm in indico/web/http_api/handlers.py:71

| Field | Value |
|---|---|
| ID | `VG-0460` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`indico/web/http_api/handlers.py:71`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/web/http_api/handlers.py#L71). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
   69      elif timestamp and abs(timestamp - int(time.time())) > ttl:
   70          raise HTTPAPIError('Signature invalid (bad timestamp)', 403)
   71      digest = hmac.new(ak.secret.encode(), normalizeQuery(path, query).encode(), hashlib.sha1).hexdigest()
   72      if signature != digest:
   73          raise HTTPAPIError('Signature invalid', 403)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/web/http_api/handlers.py:71` and, if so, apply the standard mitigation for CWE-327.

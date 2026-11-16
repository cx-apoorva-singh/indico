# Use of Broken or Risky Cryptographic Algorithm in indico/modules/events/api.py:206

| Field | Value |
|---|---|
| ID | `VG-0455` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`indico/modules/events/api.py:206`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/api.py#L206). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
  204              'db_id': convener.id,
  205              'person_id': convener.person_id,
  206              'emailHash': md5(convener.person.email.encode()).hexdigest() if convener.person.email else None
  207          }
  208          if can_manage:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/api.py:206` and, if so, apply the standard mitigation for CWE-327.

# Use of Broken or Risky Cryptographic Algorithm in indico/modules/events/contributions/schemas.py:60

| Field | Value |
|---|---|
| ID | `VG-0456` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`indico/modules/events/contributions/schemas.py:60`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/schemas.py#L60). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
   58  class ContributionPersonLinkSchema(mm.SQLAlchemyAutoSchema):
   59      affiliation_link = fields.Nested(AffiliationSchema)
   60      email_hash = fields.Function(lambda x: hashlib.md5(x.email.encode()).hexdigest() if x.email else None)
   61  
   62      class Meta:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/schemas.py:60` and, if so, apply the standard mitigation for CWE-327.

# Object Access Violation in indico/modules/users/controllers.py:744

| Field | Value |
|---|---|
| ID | `VG-0106` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/users/controllers.py:744`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/controllers.py#L744). Engine message: `Object_Access_Violation: options at indico/modules/users/util.py:223 reaches getattr at indico/modules/users/controllers.py:744`.

```py
  742                          profile_url=url_for('.user_profile', entry),
  743                          user=entry,
  744                          **{k: getattr(entry, k) for k in IDENTITY_ATTRIBUTES}
  745                      ))
  746                  else:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/controllers.py:744` and, if so, apply the standard mitigation for CWE-99.

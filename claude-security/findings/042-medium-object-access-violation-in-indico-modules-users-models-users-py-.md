# Object Access Violation in indico/modules/users/models/users.py:762

| Field | Value |
|---|---|
| ID | `VG-0107` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/users/models/users.py:762`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/models/users.py#L762). Engine message: `Object_Access_Violation: first at indico/modules/users/models/affiliations.py:99 reaches getattr at indico/modules/users/models/users.py:762`.

```py
  760          changes = {}
  761          for field in self.synced_fields:
  762              old_value = getattr(self, field)
  763              new_value = identity.data.get(field) or ''
  764              if field == 'email':
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/models/users.py:762` and, if so, apply the standard mitigation for CWE-99.

# Object Access Violation in indico/modules/users/models/users.py:784

| Field | Value |
|---|---|
| ID | `VG-0109` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/users/models/users.py:784`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/users/models/users.py#L784). Engine message: `Object_Access_Violation: first at indico/modules/users/models/affiliations.py:99 reaches setattr at indico/modules/users/models/users.py:784`.

```py
  782              else:
  783                  changes[field] = (getattr(self, field), new_value)
  784                  setattr(self, field, new_value)
  785              if not silent:
  786                  flash(_("Your {field_name} has been synchronized from '{old_value}' to '{new_value}'.").format(
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/users/models/users.py:784` and, if so, apply the standard mitigation for CWE-99.

# Object Access Violation in indico/modules/events/registration/util.py:466

| Field | Value |
|---|---|
| ID | `VG-0101` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/registration/util.py:466`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/util.py#L466). Engine message: `Object_Access_Violation: all at indico/modules/users/util.py:350 reaches setattr at indico/modules/events/registration/util.py:466`.

```py
  464                                                     billable_items_locked=billable_items_locked)
  465          for key, val in attrs.items():
  466              setattr(data_by_field[field.id], key, val)
  467          if field.type == RegistrationFormItemType.field_pd and field.personal_data_type.column:
  468              key = field.personal_data_type.column
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/util.py:466` and, if so, apply the standard mitigation for CWE-99.

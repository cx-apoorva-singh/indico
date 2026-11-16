# Object Access Violation in indico/modules/events/registration/util.py:415

| Field | Value |
|---|---|
| ID | `VG-0099` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/registration/util.py:415`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/util.py#L415). Engine message: `Object_Access_Violation: json at indico/modules/events/registration/controllers/management/reglists.py:383 reaches setattr at indico/modules/events/registration/util.py:415`.

```py
  413          registration.data.append(data_entry)
  414          for attr, field_value in form_item.field_impl.process_form_data(registration, value).items():
  415              setattr(data_entry, attr, field_value)
  416          if form_item.type == RegistrationFormItemType.field_pd and form_item.personal_data_type.column:
  417              setattr(registration, form_item.personal_data_type.column, value)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/util.py:415` and, if so, apply the standard mitigation for CWE-99.

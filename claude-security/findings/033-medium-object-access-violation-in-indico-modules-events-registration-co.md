# Object Access Violation in indico/modules/events/registration/controllers/management/fields.py:186

| Field | Value |
|---|---|
| ID | `VG-0098` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/registration/controllers/management/fields.py:186`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/management/fields.py#L186). Engine message: `Object_Access_Violation: json at indico/modules/events/registration/controllers/management/fields.py:262 reaches setattr at indico/modules/events/registration/controllers/management/fields.py:186`.

```py
  184          if old_value != value:
  185              changes[key] = (old_value, value)
  186          setattr(field, key, value)
  187      if not is_static_text:
  188          schema = field.field_impl.create_setup_schema(context=context)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/management/fields.py:186` and, if so, apply the standard mitigation for CWE-99.

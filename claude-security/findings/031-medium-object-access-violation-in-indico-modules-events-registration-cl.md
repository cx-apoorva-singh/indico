# Object Access Violation in indico/modules/events/registration/clone.py:96

| Field | Value |
|---|---|
| ID | `VG-0096` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/registration/clone.py:96`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/clone.py#L96). Engine message: `Object_Access_Violation: filter at indico/modules/events/registration/clone.py:90 reaches getattr at indico/modules/events/registration/clone.py:96`.

```py
   94              for old_item in old_section.children:
   95                  new_item = RegistrationFormItem(parent=new_section, registration_form=new_form,
   96                                                  **{attr: getattr(old_item, attr) for attr in items_attrs})
   97                  if new_item.is_field:
   98                      if clone_all_revisions:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/clone.py:96` and, if so, apply the standard mitigation for CWE-99.

# Object Access Violation in indico/modules/events/abstracts/forms.py:55

| Field | Value |
|---|---|
| ID | `VG-0090` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/abstracts/forms.py:55`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/forms.py#L55). Engine message: `Object_Access_Violation: abstract at indico/modules/events/abstracts/views.py:43 reaches setattr at indico/modules/events/abstracts/forms.py:55`.

```py
   53      for question in event.abstract_review_questions:
   54          name = f'question_{question.id}'
   55          setattr(form_class, name, question.field.create_wtf_field())
   56      return form_class
   57  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/forms.py:55` and, if so, apply the standard mitigation for CWE-99.

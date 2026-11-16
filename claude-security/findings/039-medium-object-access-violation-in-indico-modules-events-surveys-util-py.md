# Object Access Violation in indico/modules/events/surveys/util.py:37

| Field | Value |
|---|---|
| ID | `VG-0104` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/surveys/util.py:37`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/surveys/util.py#L37). Engine message: `Object_Access_Violation: one at indico/modules/events/surveys/controllers/management/questionnaire.py:375 reaches setattr at indico/modules/events/surveys/util.py:37`.

```py
   35              continue
   36          name = f'question_{question.id}'
   37          setattr(form_class, name, field_impl.create_wtf_field())
   38      return form_class
   39  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/surveys/util.py:37` and, if so, apply the standard mitigation for CWE-99.

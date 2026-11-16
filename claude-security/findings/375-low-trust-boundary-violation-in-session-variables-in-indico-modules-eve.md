# Trust Boundary Violation in Session Variables in indico/modules/events/registration/controllers/management/reglists.py:386

| Field | Value |
|---|---|
| ID | `VG-0158` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/registration/controllers/management/reglists.py:386`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/controllers/management/reglists.py#L386). Engine message: `Trust_Boundary_Violation_in_Session_Variables: json at indico/modules/events/registration/controllers/management/reglists.py:383 reaches session at indico/modules/events/registration/controllers/management/reglists.py:386`.

```py
  384          schema_cls = make_registration_schema(self.regform, management=True, override_required=override_required)
  385          form_data = load_registration_schema(self.regform, schema_cls)
  386          session['registration_notify_user_default'] = notify_user = form_data.pop('notify_user', False)
  387          create_registration(self.regform, form_data, management=True, notify_user=notify_user)
  388          flash(_('The registration was created.'), 'success')
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/controllers/management/reglists.py:386` and, if so, apply the standard mitigation for CWE-501.

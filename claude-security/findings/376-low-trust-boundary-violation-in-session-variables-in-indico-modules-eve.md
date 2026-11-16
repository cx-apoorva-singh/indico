# Trust Boundary Violation in Session Variables in indico/modules/events/registration/fields/sessions.py:54

| Field | Value |
|---|---|
| ID | `VG-0159` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/registration/fields/sessions.py:54`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/registration/fields/sessions.py#L54). Engine message: `Trust_Boundary_Violation_in_Session_Variables: all at indico/modules/events/registration/fields/sessions.py:59 reaches session_blocks at indico/modules/events/registration/fields/sessions.py:54`.

```py
   52      def filter_choices(self):
   53          event = self.form_item.registration_form.event
   54          session_blocks = (SessionBlock.query
   55                            .join(Session)
   56                            .filter(Session.event == event,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/registration/fields/sessions.py:54` and, if so, apply the standard mitigation for CWE-501.

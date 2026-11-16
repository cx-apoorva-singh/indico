# Trust Boundary Violation in Session Variables in indico/modules/events/sessions/controllers/management/__init__.py:42

| Field | Value |
|---|---|
| ID | `VG-0165` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/sessions/controllers/management/__init__.py:42`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/controllers/management/__init__.py#L42). Engine message: `Trust_Boundary_Violation_in_Session_Variables: form at indico/modules/events/sessions/controllers/management/__init__.py:42 reaches session_ids at indico/modules/events/sessions/controllers/management/__init__.py:42`.

```py
   40      def _process_args(self):
   41          RHManageSessionsBase._process_args(self)
   42          session_ids = set(map(int, request.form.getlist('session_id')))
   43          self.sessions = Session.query.with_parent(self.event).filter(Session.id.in_(session_ids)).all()
   44  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/controllers/management/__init__.py:42` and, if so, apply the standard mitigation for CWE-501.

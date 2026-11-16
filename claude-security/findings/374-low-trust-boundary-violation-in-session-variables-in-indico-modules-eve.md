# Trust Boundary Violation in Session Variables in indico/modules/events/persons/controllers.py:240

| Field | Value |
|---|---|
| ID | `VG-0157` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/persons/controllers.py:240`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/persons/controllers.py#L240). Engine message: `Trust_Boundary_Violation_in_Session_Variables: options at indico/modules/events/persons/controllers.py:245 reaches session_principal_query at indico/modules/events/persons/controllers.py:240`.

```py
  238                                     .options(contains_eager('contribution')))
  239  
  240          session_principal_query = (SessionPrincipal.query
  241                                     .filter(Session.event == self.event,
  242                                             SessionPrincipal.type == PrincipalType.email,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/persons/controllers.py:240` and, if so, apply the standard mitigation for CWE-501.

# Trust Boundary Violation in Session Variables in indico/modules/events/persons/controllers.py:75

| Field | Value |
|---|---|
| ID | `VG-0156` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/persons/controllers.py:75`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/persons/controllers.py#L75). Engine message: `Trust_Boundary_Violation_in_Session_Variables: all at indico/modules/events/persons/controllers.py:125 reaches 'title' at indico/modules/events/persons/controllers.py:75`.

```py
   73  
   74      def generate_sessions_data(self, person_link):
   75          return {'title': person_link.session_block.full_title}
   76  
   77      def generate_contributions_data(self, person_link):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/persons/controllers.py:75` and, if so, apply the standard mitigation for CWE-501.

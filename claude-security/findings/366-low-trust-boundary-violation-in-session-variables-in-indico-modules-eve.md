# Trust Boundary Violation in Session Variables in indico/modules/events/contributions/clone.py:114

| Field | Value |
|---|---|
| ID | `VG-0149` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/contributions/clone.py:114`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/clone.py#L114). Engine message: `Trust_Boundary_Violation_in_Session_Variables: one at indico/modules/events/timetable/controllers/manage.py:181 reaches IdentifierName at indico/modules/events/contributions/clone.py:114`.

```py
  112          cloner._person_map = dict(zip(event.persons, event.persons, strict=True))
  113          cloner._session_map = {contribution.session: contribution.session}
  114          cloner._session_block_map = {contribution.session_block: contribution.session_block}
  115          cloner._contrib_type_map = {contribution.type: contribution.type}
  116          cloner._contrib_field_map = dict(zip(event.contribution_fields, event.contribution_fields, strict=True))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/clone.py:114` and, if so, apply the standard mitigation for CWE-501.

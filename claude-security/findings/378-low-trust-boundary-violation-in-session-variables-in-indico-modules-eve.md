# Trust Boundary Violation in Session Variables in indico/modules/events/sessions/clone.py:60

| Field | Value |
|---|---|
| ID | `VG-0161` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/sessions/clone.py:60`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/clone.py#L60). Engine message: `Trust_Boundary_Violation_in_Session_Variables: options at indico/modules/events/sessions/clone.py:53 reaches blocks at indico/modules/events/sessions/clone.py:60`.

```py
   58              sess = Session()
   59              sess.populate_from_attrs(old_sess, attrs)
   60              sess.blocks = list(self._clone_session_blocks(old_sess.blocks, event_exists=event_exists))
   61              sess.acl_entries = clone_principals(SessionPrincipal, old_sess.acl_entries,
   62                                                  self._event_role_map, self._regform_map)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/clone.py:60` and, if so, apply the standard mitigation for CWE-501.

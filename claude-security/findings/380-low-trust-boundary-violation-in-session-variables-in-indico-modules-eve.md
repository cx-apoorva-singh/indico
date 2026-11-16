# Trust Boundary Violation in Session Variables in indico/modules/events/sessions/clone.py:64

| Field | Value |
|---|---|
| ID | `VG-0163` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/sessions/clone.py:64`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/clone.py#L64). Engine message: `Trust_Boundary_Violation_in_Session_Variables: options at indico/modules/events/sessions/clone.py:53 reaches _session_map at indico/modules/events/sessions/clone.py:64`.

```py
   62                                                  self._event_role_map, self._regform_map)
   63              new_event.sessions.append(sess)
   64              self._session_map[old_sess] = sess
   65  
   66      def _clone_session_blocks(self, blocks, event_exists=False):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/clone.py:64` and, if so, apply the standard mitigation for CWE-501.

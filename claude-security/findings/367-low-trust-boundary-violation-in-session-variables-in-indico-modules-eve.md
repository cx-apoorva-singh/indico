# Trust Boundary Violation in Session Variables in indico/modules/events/contributions/clone.py:190

| Field | Value |
|---|---|
| ID | `VG-0150` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/contributions/clone.py:190`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/clone.py#L190). Engine message: `Trust_Boundary_Violation_in_Session_Variables: options at indico/modules/events/contributions/clone.py:198 reaches session at indico/modules/events/contributions/clone.py:190`.

```py
  188          if preserve_session:
  189              if old_contrib.session is not None:
  190                  new_contrib.session = self._session_map[old_contrib.session]
  191              if old_contrib.session_block is not None:
  192                  new_contrib.session_block = self._session_block_map[old_contrib.session_block]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/clone.py:190` and, if so, apply the standard mitigation for CWE-501.

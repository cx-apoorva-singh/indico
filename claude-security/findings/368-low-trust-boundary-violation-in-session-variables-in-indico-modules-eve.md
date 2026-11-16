# Trust Boundary Violation in Session Variables in indico/modules/events/contributions/clone.py:192

| Field | Value |
|---|---|
| ID | `VG-0151` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/contributions/clone.py:192`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/clone.py#L192). Engine message: `Trust_Boundary_Violation_in_Session_Variables: options at indico/modules/events/contributions/clone.py:198 reaches session_block at indico/modules/events/contributions/clone.py:192`.

```py
  190                  new_contrib.session = self._session_map[old_contrib.session]
  191              if old_contrib.session_block is not None:
  192                  new_contrib.session_block = self._session_block_map[old_contrib.session_block]
  193          event.contributions.append(new_contrib)
  194          return new_contrib
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/clone.py:192` and, if so, apply the standard mitigation for CWE-501.

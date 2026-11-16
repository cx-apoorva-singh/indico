# Trust Boundary Violation in Session Variables in indico/modules/rb/event/controllers.py:103

| Field | Value |
|---|---|
| ID | `VG-0200` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/rb/event/controllers.py:103`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/event/controllers.py#L103). Engine message: `Trust_Boundary_Violation_in_Session_Variables: order_by at indico/modules/rb/event/controllers.py:41 reaches 'title' at indico/modules/rb/event/controllers.py:103`.

```py
  101          result = [{'id': session_block.id,
  102                     'friendly_id': session_block.session.friendly_id,
  103                     'title': session_block.full_title,
  104                     'full_title': '#{}: {} ({})'.format(  # noqa: UP032
  105                         session_block.session.friendly_id, session_block.full_title,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/event/controllers.py:103` and, if so, apply the standard mitigation for CWE-501.

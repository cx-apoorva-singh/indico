# Trust Boundary Violation in Session Variables in indico/modules/events/api.py:221

| Field | Value |
|---|---|
| ID | `VG-0144` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/api.py:221`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/api.py#L221). Engine message: `Trust_Boundary_Violation_in_Session_Variables: all at indico/modules/events/api.py:746 reaches 'title' at indico/modules/events/api.py:221`.

```py
  219              '_type': 'Session',
  220              'sessionConveners': [self._serialize_convener(c, can_manage) for c in session_.conveners],
  221              'title': session_.title,
  222              'color': f'#{session_.colors.background}',
  223              'textColor': f'#{session_.colors.text}',
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/api.py:221` and, if so, apply the standard mitigation for CWE-501.

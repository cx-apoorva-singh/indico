# Trust Boundary Violation in Session Variables in indico/modules/events/timetable/legacy.py:135

| Field | Value |
|---|---|
| ID | `VG-0186` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/timetable/legacy.py:135`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/legacy.py#L135). Engine message: `Trust_Boundary_Violation_in_Session_Variables: order_by at indico/modules/events/timetable/legacy.py:45 reaches 'description' at indico/modules/events/timetable/legacy.py:135`.

```py
  133                       'contribDuration': block.session.default_contribution_duration.seconds / 60,
  134                       'conveners': [self._get_person_data(x) for x in block.person_links],
  135                       'description': block.session.description,
  136                       'duration': block.duration.seconds / 60,
  137                       'isPoster': block.session.is_poster,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/legacy.py:135` and, if so, apply the standard mitigation for CWE-501.

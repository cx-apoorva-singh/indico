# Trust Boundary Violation in Session Variables in indico/modules/events/tracks/forms.py:33

| Field | Value |
|---|---|
| ID | `VG-0195` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/tracks/forms.py:33`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/tracks/forms.py#L33). Engine message: `Trust_Boundary_Violation_in_Session_Variables: with_parent at indico/modules/events/tracks/forms.py:33 reaches query at indico/modules/events/tracks/forms.py:33`.

```py
   31          event = kwargs.pop('event')
   32          super().__init__(*args, **kwargs)
   33          self.default_session.query = Session.query.with_parent(event)
   34          self.track_group.query = TrackGroup.query.with_parent(event)
   35  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/tracks/forms.py:33` and, if so, apply the standard mitigation for CWE-501.

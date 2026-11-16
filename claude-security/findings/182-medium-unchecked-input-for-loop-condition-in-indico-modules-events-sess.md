# Unchecked Input for Loop Condition in indico/modules/events/sessions/ical.py:83

| Field | Value |
|---|---|
| ID | `VG-0329` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/sessions/ical.py:83`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/sessions/ical.py#L83). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/sessions/ical.py:81 reaches contributions at indico/modules/events/sessions/ical.py:83`.

```py
   81                           .all())
   82          components = [generate_contribution_component(contribution, related_event_uid, organizer=organizer)
   83                        for contribution in contributions
   84                        if contribution.can_access(user)]
   85          for component in components:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/sessions/ical.py:83` and, if so, apply the standard mitigation for CWE-606.

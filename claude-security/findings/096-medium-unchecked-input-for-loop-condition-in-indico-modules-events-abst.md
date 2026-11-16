# Unchecked Input for Loop Condition in indico/modules/events/abstracts/views.py:53

| Field | Value |
|---|---|
| ID | `VG-0243` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/abstracts/views.py:53`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/views.py#L53). Engine message: `Unchecked_Input_for_Loop_Condition: event at indico/modules/events/abstracts/views.py:53 reaches tracks at indico/modules/events/abstracts/views.py:53`.

```py
   51      judgment_form = AbstractJudgmentForm(abstract=abstract, formdata=None)
   52      review_track_list_form = AbstractReviewedForTracksForm(event=abstract.event, obj=abstract, formdata=None)
   53      track_session_map = {track.id: track.default_session_id for track in abstract.event.tracks}
   54      can_manage = abstract.event.can_manage(session.user, permission='abstracts')
   55      field_values = filter_field_values(abstract.field_values, can_manage, abstract.user_owns(session.user))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/views.py:53` and, if so, apply the standard mitigation for CWE-606.

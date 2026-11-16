# Unchecked Input for Loop Condition in indico/modules/events/abstracts/controllers/management.py:179

| Field | Value |
|---|---|
| ID | `VG-0236` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/abstracts/controllers/management.py:179`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/controllers/management.py#L179). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/abstracts/controllers/management.py:177 reaches tracks at indico/modules/events/abstracts/controllers/management.py:179`.

```py
  177          tracks = Track.query.with_parent(self.event).options(subqueryload('acl_entries'))
  178          tracks_by_id = {str(track.id): track for track in tracks}
  179          for track in tracks:
  180              roles[str(track.id)] = track_permissions_schema.dump(track).get('acl_entries', {})
  181          form = AbstractReviewingRolesForm(event=self.event, obj=FormDefaults(roles=roles))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/controllers/management.py:179` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/events/abstracts/util.py:270

| Field | Value |
|---|---|
| ID | `VG-0239` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/abstracts/util.py:270`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/util.py#L270). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/abstracts/util.py:266 reaches tracks at indico/modules/events/abstracts/util.py:270`.

```py
  268              event.can_manage(user, permission='convene_all_abstracts', explicit_permission=True)):
  269          return tracks
  270      return [track for track in tracks if
  271              (track.can_manage(user, permission='review', explicit_permission=True) or
  272               track.can_manage(user, permission='convene', explicit_permission=True))]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/util.py:270` and, if so, apply the standard mitigation for CWE-606.

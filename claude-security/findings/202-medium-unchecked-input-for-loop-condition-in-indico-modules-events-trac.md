# Unchecked Input for Loop Condition in indico/modules/events/tracks/controllers.py:115

| Field | Value |
|---|---|
| ID | `VG-0349` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/tracks/controllers.py:115`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/tracks/controllers.py#L115). Engine message: `Unchecked_Input_for_Loop_Condition: json at indico/modules/events/tracks/controllers.py:112 reaches enumerate at indico/modules/events/tracks/controllers.py:115`.

```py
  113          tracks = {t.id: t for t in self.event.tracks}
  114          track_groups = {tg.id: tg for tg in self.event.track_groups}
  115          for position, item in enumerate(sort_order, 1):
  116              if item['type'] == 'track':
  117                  tracks[item['id']].position = position
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/tracks/controllers.py:115` and, if so, apply the standard mitigation for CWE-606.

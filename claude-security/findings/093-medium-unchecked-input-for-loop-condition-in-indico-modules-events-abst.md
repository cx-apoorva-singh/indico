# Unchecked Input for Loop Condition in indico/modules/events/abstracts/util.py:308

| Field | Value |
|---|---|
| ID | `VG-0240` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/abstracts/util.py:308`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/util.py#L308). Engine message: `Unchecked_Input_for_Loop_Condition: group_by at indico/modules/events/abstracts/util.py:306 reaches query at indico/modules/events/abstracts/util.py:308`.

```py
  306               .group_by(Track.id))
  307      return {track: {'total': total, 'reviewed': reviewed, 'unreviewed': unreviewed}
  308              for track, total, reviewed, unreviewed in query}
  309  
  310  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/util.py:308` and, if so, apply the standard mitigation for CWE-606.

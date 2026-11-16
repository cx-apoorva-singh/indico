# Unchecked Input for Loop Condition in indico/util/suggestions.py:127

| Field | Value |
|---|---|
| ID | `VG-0435` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/util/suggestions.py:127`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/util/suggestions.py#L127). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/util/suggestions.py:125 reaches attended at indico/util/suggestions.py:127`.

```py
  125                  .all())
  126      categ_events = defaultdict(list)
  127      for event in attended:
  128          categ_events[event.category].append(event)
  129      return {categ: _get_category_score(user, categ, events, debug) for categ, events in categ_events.items()}
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/util/suggestions.py:127` and, if so, apply the standard mitigation for CWE-606.

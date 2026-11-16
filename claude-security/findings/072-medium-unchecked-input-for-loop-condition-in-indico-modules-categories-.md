# Unchecked Input for Loop Condition in indico/modules/categories/controllers/display.py:603

| Field | Value |
|---|---|
| ID | `VG-0219` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/categories/controllers/display.py:603`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/controllers/display.py#L603). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/categories/controllers/display.py:601 reaches raw_locations at indico/modules/categories/controllers/display.py:603`.

```py
  601          raw_locations = Location.query.options(load_only('id', 'name')).all()
  602          allow_keywords = bool(allowed_keywords)
  603          locations = [{'title': loc.name, 'id': loc.id} for loc in raw_locations]
  604          ongoing_events = (Event.query
  605                            .filter(Event.is_visible_in(self.category.id),
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/controllers/display.py:603` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/events/util.py:609

| Field | Value |
|---|---|
| ID | `VG-0351` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/util.py:609`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/util.py#L609). Engine message: `Unchecked_Input_for_Loop_Condition: scalar at indico/modules/categories/controllers/util.py:117 reaches events at indico/modules/events/util.py:609`.

```py
  607      query = (EventSetting.query
  608               .filter_by(module='language', name='default_locale')
  609               .filter(EventSetting.event_id.in_(e.id for e in events)))
  610      default_locales = {x.event: x.value for x in query}
  611      for event in events:
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/util.py:609` and, if so, apply the standard mitigation for CWE-606.

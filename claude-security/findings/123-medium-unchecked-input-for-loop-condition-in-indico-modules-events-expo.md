# Unchecked Input for Loop Condition in indico/modules/events/export.py:845

| Field | Value |
|---|---|
| ID | `VG-0270` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/export.py:845`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/export.py#L845). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/export.py:844 reaches verbose_iterator at indico/modules/events/export.py:845`.

```py
  843                          'Category imported from another Indico instance')
  844                  events = Event.query.filter(Event.category_chain_overlaps([cat.id])).all()
  845                  for event in verbose_iterator(events, len(events), attrgetter('id'), attrgetter('title'),
  846                                                print_total_time=True):
  847                      event.log(EventLogRealm.event, LogKind.other, 'Event',
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/export.py:845` and, if so, apply the standard mitigation for CWE-606.

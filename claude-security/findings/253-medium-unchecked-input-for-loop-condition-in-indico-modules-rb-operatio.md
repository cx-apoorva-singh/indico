# Unchecked Input for Loop Condition in indico/modules/rb/operations/suggestions.py:30

| Field | Value |
|---|---|
| ID | `VG-0400` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/suggestions.py:30`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/suggestions.py#L30). Engine message: `Unchecked_Input_for_Loop_Condition: scalar_subquery at indico/modules/rb/operations/rooms.py:169 reaches search_for_rooms at indico/modules/rb/operations/suggestions.py:30`.

```py
   28  def get_suggestions(filters, limit=None):
   29      blocked_rooms = get_blocked_rooms(filters['start_dt'], filters['end_dt'], [BlockedRoomState.accepted])
   30      rooms = [room for room in search_for_rooms(filters, availability=False) if room not in blocked_rooms]
   31      if filters['repeat_frequency'] == RepeatFrequency.NEVER:
   32          suggestions = sort_suggestions(get_single_booking_suggestions(rooms, filters['start_dt'], filters['end_dt'],
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/suggestions.py:30` and, if so, apply the standard mitigation for CWE-606.

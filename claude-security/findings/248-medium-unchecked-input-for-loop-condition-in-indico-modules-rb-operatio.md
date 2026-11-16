# Unchecked Input for Loop Condition in indico/modules/rb/operations/misc.py:18

| Field | Value |
|---|---|
| ID | `VG-0395` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/misc.py:18`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/misc.py#L18). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/controllers/backend/bookings.py:77 reaches rooms at indico/modules/rb/operations/misc.py:18`.

```py
   16  
   17  def get_rooms_unbookable_hours(rooms):
   18      room_ids = [room.id for room in rooms]
   19      query = BookableHours.query.filter(BookableHours.room_id.in_(room_ids))
   20      rooms_hours = group_list(query, key=attrgetter('room_id'), sort_by=attrgetter('room_id'))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/misc.py:18` and, if so, apply the standard mitigation for CWE-606.

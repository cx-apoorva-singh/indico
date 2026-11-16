# Unchecked Input for Loop Condition in indico/modules/rb/controllers/backend/bookings.py:79

| Field | Value |
|---|---|
| ID | `VG-0362` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/controllers/backend/bookings.py:79`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/controllers/backend/bookings.py#L79). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/controllers/backend/bookings.py:77 reaches date_range at indico/modules/rb/controllers/backend/bookings.py:79`.

```py
   77          rooms = [self.room] if self.room else Room.query.filter(Room.id.in_(room_ids), ~Room.is_deleted).all()
   78          date_range, availability = get_rooms_availability(rooms, **kwargs)
   79          date_range = [dt.isoformat() for dt in date_range]
   80  
   81          for data in availability.values():
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/controllers/backend/bookings.py:79` and, if so, apply the standard mitigation for CWE-606.

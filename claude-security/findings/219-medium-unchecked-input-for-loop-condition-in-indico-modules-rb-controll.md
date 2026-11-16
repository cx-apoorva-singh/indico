# Unchecked Input for Loop Condition in indico/modules/rb/controllers/backend/rooms.py:77

| Field | Value |
|---|---|
| ID | `VG-0366` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/controllers/backend/rooms.py:77`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/controllers/backend/rooms.py#L77). Engine message: `Unchecked_Input_for_Loop_Condition: scalar_subquery at indico/modules/rb/operations/rooms.py:169 reaches rooms at indico/modules/rb/controllers/backend/rooms.py:77`.

```py
   75          # We can't filter by blocking's acl in the search_query, so we need to adjust the results
   76          rooms = self._adjust_blockings(rooms, args, availability, admin_override_enabled)
   77          room_ids = [room[0] for room in rooms]
   78          if filter_availability:
   79              room_ids_without_availability_filter = [
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/controllers/backend/rooms.py:77` and, if so, apply the standard mitigation for CWE-606.

# Unchecked Input for Loop Condition in indico/modules/rb/operations/bookings.py:129

| Field | Value |
|---|---|
| ID | `VG-0389` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/bookings.py:129`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/bookings.py#L129). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/rb/controllers/backend/bookings.py:77 reaches rooms at indico/modules/rb/operations/bookings.py:129`.

```py
  127      )
  128      dates = [candidate.start_dt.date() for candidate in candidates]
  129      for room in rooms:
  130          room_occurrences = occurrences.get(room.id, [])
  131          room_conflicting_candidates = conflicting_candidates.get(room.id, [])
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/bookings.py:129` and, if so, apply the standard mitigation for CWE-606.

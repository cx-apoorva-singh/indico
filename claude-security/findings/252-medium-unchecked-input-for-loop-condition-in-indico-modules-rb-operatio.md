# Unchecked Input for Loop Condition in indico/modules/rb/operations/rooms.py:198

| Field | Value |
|---|---|
| ID | `VG-0399` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/operations/rooms.py:198`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/operations/rooms.py#L198). Engine message: `Unchecked_Input_for_Loop_Condition: scalar_subquery at indico/modules/rb/operations/rooms.py:169 reaches filter at indico/modules/rb/operations/rooms.py:198`.

```py
  196                              selected_period_days <= booking_limit_days))
  197          unbookable_ids = [room.id
  198                            for room in query.filter(db.and_(*availability_filters), ~criterion)
  199                            if not room.can_override(session.user, allow_admin=False)]
  200          availability_filters.append(~Room.id.in_(unbookable_ids))
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/operations/rooms.py:198` and, if so, apply the standard mitigation for CWE-606.

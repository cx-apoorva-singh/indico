# Unchecked Input for Loop Condition in indico/modules/rb/event/controllers.py:107

| Field | Value |
|---|---|
| ID | `VG-0376` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/event/controllers.py:107`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/event/controllers.py#L107). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/rb/event/controllers.py:41 reaches query at indico/modules/rb/event/controllers.py:107`.

```py
  105                         session_block.session.friendly_id, session_block.full_title,
  106                         format_datetime(session_block.timetable_entry.start_dt))}
  107                    for session_block in query]
  108          return jsonify(result)
  109  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/event/controllers.py:107` and, if so, apply the standard mitigation for CWE-606.

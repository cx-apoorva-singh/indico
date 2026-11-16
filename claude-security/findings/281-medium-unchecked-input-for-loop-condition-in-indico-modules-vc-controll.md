# Unchecked Input for Loop Condition in indico/modules/vc/controllers.py:376

| Field | Value |
|---|---|
| ID | `VG-0428` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/vc/controllers.py:376`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/vc/controllers.py#L376). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/vc/util.py:54 reaches results at indico/modules/vc/controllers.py:376`.

```py
  374              to_dt = as_utc(get_day_end(form.end_date.data)) if form.end_date.data else None
  375              results = find_event_vc_rooms(from_dt=from_dt, to_dt=to_dt, distinct=True)
  376              results = group_list((r for r in results if r.event),
  377                                   key=lambda r: r.event.start_dt.date(),
  378                                   sort_by=lambda r: r.event.start_dt,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/vc/controllers.py:376` and, if so, apply the standard mitigation for CWE-606.

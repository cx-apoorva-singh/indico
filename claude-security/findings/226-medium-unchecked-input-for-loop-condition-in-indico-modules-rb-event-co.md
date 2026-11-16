# Unchecked Input for Loop Condition in indico/modules/rb/event/controllers.py:65

| Field | Value |
|---|---|
| ID | `VG-0373` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/rb/event/controllers.py:65`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/rb/event/controllers.py#L65). Engine message: `Unchecked_Input_for_Loop_Condition: order_by at indico/modules/rb/event/controllers.py:32 reaches _contrib_query at indico/modules/rb/event/controllers.py:65`.

```py
   63  
   64          contribs_data = {c.id: {'start_dt': c.start_dt.isoformat(), 'end_dt': c.end_dt.isoformat()}
   65                           for c in _contrib_query(self.event)}
   66          session_blocks_data = {sb.id: {'start_dt': sb.start_dt.isoformat(), 'end_dt': sb.end_dt.isoformat()}
   67                                 for sb in _session_block_query(self.event)}
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/rb/event/controllers.py:65` and, if so, apply the standard mitigation for CWE-606.

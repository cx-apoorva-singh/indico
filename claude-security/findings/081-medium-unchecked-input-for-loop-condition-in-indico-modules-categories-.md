# Unchecked Input for Loop Condition in indico/modules/categories/util.py:162

| Field | Value |
|---|---|
| ID | `VG-0228` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/categories/util.py:162`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/util.py#L162). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/categories/util.py:146 reaches query at indico/modules/categories/util.py:162`.

```py
  160               .order_by(db.desc('weight'), Event.start_dt, Event.title)
  161               .limit(data['max_entries']))
  162      for row in query:
  163          event = row[0]
  164          # we cache the result of the function and is_deleted is used in the repr
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/util.py:162` and, if so, apply the standard mitigation for CWE-606.

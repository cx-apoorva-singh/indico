# Unchecked Input for Loop Condition in indico/modules/events/contributions/lists.py:223

| Field | Value |
|---|---|
| ID | `VG-0259` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/contributions/lists.py:223`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/lists.py#L223). Engine message: `Unchecked_Input_for_Loop_Condition: options at indico/modules/events/contributions/lists.py:108 reaches contributions_query at indico/modules/events/contributions/lists.py:223`.

```py
  221          list_config = self._get_config()
  222          contributions_query = self._build_query()
  223          total_entries = (sum(1 for c in contributions_query if c.can_access(session.user)) if self.check_access else
  224                           contributions_query.count())
  225          contributions = [c for c in self._filter_list_entries(contributions_query, list_config['filters'])
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/lists.py:223` and, if so, apply the standard mitigation for CWE-606.

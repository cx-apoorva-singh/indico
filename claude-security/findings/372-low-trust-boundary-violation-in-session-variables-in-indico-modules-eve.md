# Trust Boundary Violation in Session Variables in indico/modules/events/contributions/lists.py:238

| Field | Value |
|---|---|
| ID | `VG-0155` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-501 |
| Rule | `Python_Trust_Boundary_Violation_in_Session_Variables` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Trust_Boundary_Violation_in_Session_Variables` (CWE-501) reports an issue at [`indico/modules/events/contributions/lists.py:238`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/lists.py#L238). Engine message: `Trust_Boundary_Violation_in_Session_Variables: all at indico/modules/events/contributions/lists.py:89 reaches 'sessions' at indico/modules/events/contributions/lists.py:238`.

```py
  236          dynamic_columns = self._get_sorted_custom_fields(dynamic_item_ids)
  237          has_types = bool(self.event.contribution_types.all())
  238          return {'contribs': contributions, 'sessions': sessions, 'tracks': tracks, 'total_entries': total_entries,
  239                  'total_duration': total_duration, 'selected_entry': selected_entry,
  240                  'registered_persons': registered_persons, 'static_columns': static_columns,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/lists.py:238` and, if so, apply the standard mitigation for CWE-501.

# Log Forging in indico/modules/events/contributions/clone.py:126

| Field | Value |
|---|---|
| ID | `VG-0069` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/contributions/clone.py:126`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/clone.py#L126). Engine message: `Log_Forging: args at indico/modules/events/timetable/controllers/manage.py:180 reaches info at indico/modules/events/contributions/clone.py:126`.

```py
  124          signals.event.contribution_created.send(new_contribution, cloned_from=contribution,
  125                                                  person_link_map=cloner._person_link_map)
  126          contributions_logger.info('Contribution %s created by %s (from %s)', new_contribution, session.user,
  127                                    contribution)
  128          new_contribution.log(
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/clone.py:126` and, if so, apply the standard mitigation for CWE-117.

# Log Forging in indico/modules/events/surveys/controllers/management/questionnaire.py:355

| Field | Value |
|---|---|
| ID | `VG-0078` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/surveys/controllers/management/questionnaire.py:355`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/surveys/controllers/management/questionnaire.py#L355). Engine message: `Log_Forging: form at indico/modules/events/surveys/controllers/management/questionnaire.py:334 reaches info at indico/modules/events/surveys/controllers/management/questionnaire.py:355`.

```py
  353                  item.parent = section
  354                  logger.info('Item %s moved to section %s by %s', item, section, session.user)
  355          logger.info('Items in %s reordered by %s', section, session.user)
  356          if changed_section is not None:
  357              for position, item in enumerate(changed_section.children, 1):
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/surveys/controllers/management/questionnaire.py:355` and, if so, apply the standard mitigation for CWE-117.

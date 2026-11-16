# Log Forging in indico/modules/events/abstracts/operations.py:245

| Field | Value |
|---|---|
| ID | `VG-0068` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/modules/events/abstracts/operations.py:245`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/operations.py#L245). Engine message: `Log_Forging: form at indico/modules/events/abstracts/controllers/abstract_list.py:80 reaches info at indico/modules/events/abstracts/operations.py:245`.

```py
  243      if send_notifications:
  244          log_data['Notifications sent'] = send_abstract_notifications(abstract)
  245      logger.info('Abstract %s judged by %s', abstract, judge)
  246      abstract.log(EventLogRealm.reviewing, LogKind.change, 'Abstracts',
  247                   f'Abstract {abstract.verbose_title} judged', judge, data=log_data)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/operations.py:245` and, if so, apply the standard mitigation for CWE-117.

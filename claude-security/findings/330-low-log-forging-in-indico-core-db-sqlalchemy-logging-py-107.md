# Log Forging in indico/core/db/sqlalchemy/logging.py:107

| Field | Value |
|---|---|
| ID | `VG-0064` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/core/db/sqlalchemy/logging.py:107`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/db/sqlalchemy/logging.py#L107). Engine message: `Log_Forging: path at indico/core/db/sqlalchemy/logging.py:108 reaches debug at indico/core/db/sqlalchemy/logging.py:107`.

```py
  105          source_line = _get_sql_line()
  106          source = source_line['items'] if source_line else None
  107          logger.debug('Query complete; total time: %s', total, extra={'sql_log_type': 'end',
  108                                                                       'req_path': (request.path
  109                                                                                    if has_request_context()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/db/sqlalchemy/logging.py:107` and, if so, apply the standard mitigation for CWE-117.

# Log Forging in indico/core/db/sqlalchemy/logging.py:124

| Field | Value |
|---|---|
| ID | `VG-0065` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/core/db/sqlalchemy/logging.py:124`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/db/sqlalchemy/logging.py#L124). Engine message: `Log_Forging: method at indico/core/db/sqlalchemy/logging.py:127 reaches debug at indico/core/db/sqlalchemy/logging.py:124`.

```py
  122          if not stats['query_count']:
  123              return
  124          logger.debug('Request finished', extra={'sql_log_type': 'end_request',
  125                                                  'sql_query_count': stats['query_count'],
  126                                                  'repl': app.config.get('REPL'),
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/db/sqlalchemy/logging.py:124` and, if so, apply the standard mitigation for CWE-117.

# Log Forging in indico/core/db/sqlalchemy/logging.py:69

| Field | Value |
|---|---|
| ID | `VG-0062` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/core/db/sqlalchemy/logging.py:69`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/db/sqlalchemy/logging.py#L69). Engine message: `Log_Forging: method at indico/core/db/sqlalchemy/logging.py:71 reaches debug at indico/core/db/sqlalchemy/logging.py:69`.

```py
   67          if not g.get('req_start_sent'):
   68              g.req_start_sent = True
   69              logger.debug('Request started', extra={'sql_log_type': 'start_request',
   70                                                     'repl': app.config.get('REPL'),
   71                                                     'req_verb': request.method if has_request_context() else None,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/db/sqlalchemy/logging.py:69` and, if so, apply the standard mitigation for CWE-117.

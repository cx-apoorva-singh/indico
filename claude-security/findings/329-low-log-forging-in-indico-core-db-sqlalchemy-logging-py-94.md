# Log Forging in indico/core/db/sqlalchemy/logging.py:94

| Field | Value |
|---|---|
| ID | `VG-0063` |
| Severity | **Low** |
| Status | open |
| CWE | CWE-117 |
| Rule | `Python_Log_Forging` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Log_Forging` (CWE-117) reports an issue at [`indico/core/db/sqlalchemy/logging.py:94`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/db/sqlalchemy/logging.py#L94). Engine message: `Log_Forging: path at indico/core/db/sqlalchemy/logging.py:96 reaches debug at indico/core/db/sqlalchemy/logging.py:94`.

```py
   92          else:
   93              parameters = tuple(_fix_param(v) for v in parameters)
   94          logger.debug(log_msg,
   95                       extra={'sql_log_type': 'start',
   96                              'req_path': request.path if has_request_context() else None,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/db/sqlalchemy/logging.py:94` and, if so, apply the standard mitigation for CWE-117.

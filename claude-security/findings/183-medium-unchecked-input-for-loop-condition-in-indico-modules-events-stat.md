# Unchecked Input for Loop Condition in indico/modules/events/static/tasks.py:73

| Field | Value |
|---|---|
| ID | `VG-0330` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/static/tasks.py:73`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/static/tasks.py#L73). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/events/static/tasks.py:70 reaches expired_sites at indico/modules/events/static/tasks.py:73`.

```py
   71      logger.info('Removing %d expired static sites from the past %d days', len(expired_sites), days)
   72      try:
   73          for site in expired_sites:
   74              try:
   75                  site.delete()
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/static/tasks.py:73` and, if so, apply the standard mitigation for CWE-606.

# Command Injection in bin/utils/db_diff.py:135

| Field | Value |
|---|---|
| ID | `VG-0044` |
| Severity | **High** |
| Status | open |
| CWE | CWE-77 |
| Rule | `Python_Command_Injection` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Command_Injection` (CWE-77) reports an issue at [`bin/utils/db_diff.py:135`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/utils/db_diff.py#L135). Engine message: `Command_Injection: diff`.

```py
  133      else:
  134          pretty_diff = _checked_call(verbose, ['pygmentize', '-l', 'sql', '-f', 'terminal256',
  135                                                '-O', 'style=native,bg=dark'], return_output=True, input=diff)
  136          click.echo(pretty_diff)
  137  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/utils/db_diff.py:135` and, if so, apply the standard mitigation for CWE-77.

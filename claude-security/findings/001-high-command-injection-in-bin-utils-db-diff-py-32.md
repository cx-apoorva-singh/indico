# Command Injection in bin/utils/db_diff.py:32

| Field | Value |
|---|---|
| ID | `VG-0043` |
| Severity | **High** |
| Status | open |
| CWE | CWE-77 |
| Rule | `Python_Command_Injection` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Command_Injection` (CWE-77) reports an issue at [`bin/utils/db_diff.py:32`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/utils/db_diff.py#L32). Engine message: `Command_Injection: input`.

```py
   30          kwargs['env'] = os.environ | env
   31      try:
   32          rv = subprocess.check_output(args, stderr=subprocess.STDOUT, input=input, text=True, **kwargs).strip()
   33      except OSError as exc:
   34          click.echo(click.style(f'!! {cmd} failed: {exc}', fg='red', bold=True), err=True)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/utils/db_diff.py:32` and, if so, apply the standard mitigation for CWE-77.

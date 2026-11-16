# Unchecked Input for Loop Condition in indico/cli/maintenance.py:31

| Field | Value |
|---|---|
| ID | `VG-0210` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/cli/maintenance.py:31`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/cli/maintenance.py#L31). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/cli/maintenance.py:56 reaches principals at indico/cli/maintenance.py:31`.

```py
   29  def _fix_role_principals(principals, get_event):
   30      role_attrs = get_simple_column_attrs(EventRole) | {'members'}
   31      for p in principals:
   32          click.echo(f'Fixing {p}')
   33          event = get_event(p)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/cli/maintenance.py:31` and, if so, apply the standard mitigation for CWE-606.

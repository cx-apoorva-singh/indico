# Unchecked Input for Loop Condition in indico/cli/event.py:195

| Field | Value |
|---|---|
| ID | `VG-0209` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/cli/event.py:195`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/cli/event.py#L195). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/cli/event.py:181 reaches events at indico/cli/event.py:195`.

```py
  193  
  194      click.echo('Selected events:')
  195      for event in events:
  196          click.echo(format_event(event))
  197  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/cli/event.py:195` and, if so, apply the standard mitigation for CWE-606.

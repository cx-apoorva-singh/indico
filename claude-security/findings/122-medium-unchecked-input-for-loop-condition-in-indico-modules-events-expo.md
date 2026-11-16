# Unchecked Input for Loop Condition in indico/modules/events/export.py:157

| Field | Value |
|---|---|
| ID | `VG-0269` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/export.py:157`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/export.py#L157). Engine message: `Unchecked_Input_for_Loop_Condition: load at indico/modules/events/export.py:156 reaches mapping at indico/modules/events/export.py:157`.

```py
  155  
  156      mapping = pickle.load(mapping_file)  # noqa: S301
  157      backend_names = {x[0][0] for x in mapping}
  158      click.echo(f'Config is needed for external storage backends: {', '.join(sorted(backend_names))}')
  159      backends = _prompt_storage_backend_config(backend_names)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/export.py:157` and, if so, apply the standard mitigation for CWE-606.

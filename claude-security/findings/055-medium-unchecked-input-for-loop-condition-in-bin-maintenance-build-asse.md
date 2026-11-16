# Unchecked Input for Loop Condition in bin/maintenance/build-assets.py:87

| Field | Value |
|---|---|
| ID | `VG-0202` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`bin/maintenance/build-assets.py:87`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/maintenance/build-assets.py#L87). Engine message: `Unchecked_Input_for_Loop_Condition: load at bin/maintenance/build-assets.py:65 reaches items at bin/maintenance/build-assets.py:87`.

```py
   85      core_data = re.sub(r'^(\S+:)$', r'__core_\1', core_data, flags=re.MULTILINE)
   86      settings = {k: v
   87                  for k, v in yaml.safe_load(core_data + '\n' + plugin_yaml).items()
   88                  if not k.startswith('__core_')}
   89      return {name: {'stylesheet': theme['stylesheet'], 'print_stylesheet': theme.get('print_stylesheet')}
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/maintenance/build-assets.py:87` and, if so, apply the standard mitigation for CWE-606.

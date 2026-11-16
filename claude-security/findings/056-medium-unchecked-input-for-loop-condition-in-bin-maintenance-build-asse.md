# Unchecked Input for Loop Condition in bin/maintenance/build-assets.py:230

| Field | Value |
|---|---|
| ID | `VG-0203` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`bin/maintenance/build-assets.py:230`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/maintenance/build-assets.py#L230). Engine message: `Unchecked_Input_for_Loop_Condition: load at bin/maintenance/build-assets.py:75 reaches _get_plugin_build_deps at bin/maintenance/build-assets.py:230`.

```py
  228      url_map_path = webpack_build_config['build']['urlMapPath']
  229      dump_plugin_args = ['--plugin', webpack_build_config['plugin']]
  230      for name in _get_plugin_build_deps(plugin_dir):
  231          dump_plugin_args += ['--plugin', name]
  232      subprocess.check_call([sys.executable, 'bin/maintenance/dump_url_map.py', '--output', url_map_path,
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/maintenance/build-assets.py:230` and, if so, apply the standard mitigation for CWE-606.

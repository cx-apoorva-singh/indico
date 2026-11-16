# Stored Command Injection in bin/maintenance/build-assets.py:232

| Field | Value |
|---|---|
| ID | `VG-0129` |
| Severity | **High** |
| Status | open |
| CWE | CWE-77 |
| Rule | `Python_Stored_Command_Injection` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Stored_Command_Injection` (CWE-77) reports an issue at [`bin/maintenance/build-assets.py:232`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/bin/maintenance/build-assets.py#L232). Engine message: `Stored_Command_Injection: load at bin/maintenance/build-assets.py:75 reaches check_call at bin/maintenance/build-assets.py:232`.

```py
  230      for name in _get_plugin_build_deps(plugin_dir):
  231          dump_plugin_args += ['--plugin', name]
  232      subprocess.check_call([sys.executable, 'bin/maintenance/dump_url_map.py', '--output', url_map_path,
  233                             *dump_plugin_args, *force_url_map])
  234      webpack_config_file = plugin_dir / 'webpack.config.mjs'
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `bin/maintenance/build-assets.py:232` and, if so, apply the standard mitigation for CWE-77.

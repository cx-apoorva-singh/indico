# Unchecked Input for Loop Condition in indico/modules/events/util.py:728

| Field | Value |
|---|---|
| ID | `VG-0354` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/util.py:728`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/util.py#L728). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/attachments/tasks.py:20 reaches _iter_items at indico/modules/events/util.py:728`.

```py
  726          with ZipFile(temp_file.name, 'w', allowZip64=True) as zip_handler:
  727              self.used_filenames = set()
  728              for item in self._iter_items(files_holder):
  729                  name = self._prepare_folder_structure(item)
  730                  self.used_filenames.add(name)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/util.py:728` and, if so, apply the standard mitigation for CWE-606.

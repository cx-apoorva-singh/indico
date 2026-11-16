# Unchecked Input for Loop Condition in indico/modules/events/editing/__init__.py:41

| Field | Value |
|---|---|
| ID | `VG-0264` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/editing/__init__.py:41`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/editing/__init__.py#L41). Engine message: `Unchecked_Input_for_Loop_Condition: with_parent at indico/modules/events/editing/__init__.py:39 reaches types_without_filetypes at indico/modules/events/editing/__init__.py:41`.

```py
   39          types_with_filetypes = {type_ for type_, in db.session.query(EditingFileType.type).with_parent(event)}
   40          types_without_filetypes = set(EditableType) - types_with_filetypes
   41          for type_ in types_without_filetypes:
   42              ft = EditingFileType(name='PDF', extensions=['pdf'], publishable=True, required=True, type=type_)
   43              event.editing_file_types.append(ft)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/editing/__init__.py:41` and, if so, apply the standard mitigation for CWE-606.

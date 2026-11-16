# Object Access Violation in indico/modules/events/layout/clone.py:68

| Field | Value |
|---|---|
| ID | `VG-0093` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/layout/clone.py:68`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/layout/clone.py#L68). Engine message: `Object_Access_Violation: all at indico/modules/events/layout/models/menu.py:386 reaches getattr at indico/modules/events/layout/clone.py:68`.

```py
   66      def _copy_menu_entry(self, menu_entry, new_event, parent=None, include_children=True):
   67          base_columns = get_attrs_to_clone(MenuEntry)
   68          new_menu_entry = MenuEntry(**{col: getattr(menu_entry, col) for col in base_columns})
   69          if menu_entry.is_page:
   70              with db.session.no_autoflush:  # menu_entry.page is lazy-loaded
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/layout/clone.py:68` and, if so, apply the standard mitigation for CWE-99.

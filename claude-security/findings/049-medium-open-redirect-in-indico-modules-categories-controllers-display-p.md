# Open Redirect in indico/modules/categories/controllers/display.py:699

| Field | Value |
|---|---|
| ID | `VG-0114` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-601 |
| Rule | `Python_Open_Redirect` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Open_Redirect` (CWE-601) reports an issue at [`indico/modules/categories/controllers/display.py:699`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/categories/controllers/display.py#L699). Engine message: `Open_Redirect: read at docs/source/conf.py:33 reaches redirect at indico/modules/categories/controllers/display.py:699`.

```py
  697          event = self._get_event()
  698          if event:
  699              return redirect(event.url)
  700          else:
  701              flash(self._no_event_message)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/categories/controllers/display.py:699` and, if so, apply the standard mitigation for CWE-601.

# Object Access Violation in indico/modules/events/abstracts/operations.py:283

| Field | Value |
|---|---|
| ID | `VG-0091` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/abstracts/operations.py:283`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/operations.py#L283). Engine message: `Object_Access_Violation: form at indico/modules/events/abstracts/controllers/abstract_list.py:80 reaches setattr at indico/modules/events/abstracts/operations.py:283`.

```py
  281              for column_name in ('_title', '_affiliation', '_affiliation_id', '_address', '_phone', '_first_name',
  282                                  '_last_name'):
  283                  setattr(link, column_name, getattr(source_link, column_name))
  284  
  285      # Add new links in order
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/operations.py:283` and, if so, apply the standard mitigation for CWE-99.

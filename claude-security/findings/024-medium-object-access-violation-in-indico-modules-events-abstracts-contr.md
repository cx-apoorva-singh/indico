# Object Access Violation in indico/modules/events/abstracts/controllers/abstract_list.py:135

| Field | Value |
|---|---|
| ID | `VG-0089` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-99 |
| Rule | `Python_Object_Access_Violation` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Object_Access_Violation` (CWE-99) reports an issue at [`indico/modules/events/abstracts/controllers/abstract_list.py:135`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/abstracts/controllers/abstract_list.py#L135). Engine message: `Object_Access_Violation: first_or_404 at indico/modules/events/abstracts/controllers/abstract_list.py:154 reaches getattr at indico/modules/events/abstracts/controllers/abstract_list.py:135`.

```py
  133      def clone_fields(self, abstract):
  134          field_names = ['title', 'description', 'submission_comment', 'submitted_for_tracks', 'submitted_contrib_type']
  135          field_data = {f: getattr(abstract, f) for f in field_names}
  136          person_links = []
  137          link_attrs = get_attrs_to_clone(AbstractPersonLink)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/abstracts/controllers/abstract_list.py:135` and, if so, apply the standard mitigation for CWE-99.

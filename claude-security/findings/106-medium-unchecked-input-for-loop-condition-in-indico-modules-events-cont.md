# Unchecked Input for Loop Condition in indico/modules/events/contributions/controllers/display.py:104

| Field | Value |
|---|---|
| ID | `VG-0253` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/contributions/controllers/display.py:104`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/controllers/display.py#L104). Engine message: `Unchecked_Input_for_Loop_Condition: filter at indico/modules/events/contributions/util.py:259 reaches contribs at indico/modules/events/contributions/controllers/display.py:104`.

```py
  102          contribs = get_contributions_for_user(self.event, session.user)
  103          categorized = defaultdict(set)
  104          for contrib in contribs:
  105              added = False
  106              links = [link for link in contrib.person_links if link.person.user == session.user]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/controllers/display.py:104` and, if so, apply the standard mitigation for CWE-606.

# Use of Broken or Risky Cryptographic Algorithm in indico/modules/events/timetable/legacy.py:290

| Field | Value |
|---|---|
| ID | `VG-0457` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-327 |
| Rule | `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Use_of_Broken_or_Risky_Cryptographic_Algorithm` (CWE-327) reports an issue at [`indico/modules/events/timetable/legacy.py:290`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/timetable/legacy.py#L290). Engine message: `Use_of_Broken_or_Risky_Cryptographic_Algorithm: hexdigest`.

```py
  288                  'familyName': person_link.last_name,
  289                  'affiliation': person_link.affiliation,
  290                  'emailHash': md5(person.email.encode()).hexdigest() if person.email else None,
  291                  'name': person_link.get_full_name(last_name_first=False, last_name_upper=False,
  292                                                    abbrev_first_name=False, show_title=person.event.show_titles),
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/timetable/legacy.py:290` and, if so, apply the standard mitigation for CWE-327.

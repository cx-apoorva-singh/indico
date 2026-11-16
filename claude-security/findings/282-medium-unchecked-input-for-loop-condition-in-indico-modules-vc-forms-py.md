# Unchecked Input for Loop Condition in indico/modules/vc/forms.py:98

| Field | Value |
|---|---|
| ID | `VG-0429` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/vc/forms.py:98`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/vc/forms.py#L98). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/vc/forms.py:95 reaches sorted at indico/modules/vc/forms.py:98`.

```py
   96          block_choices = [(block.id, '{} ({})'.format(block.full_title,  # noqa: UP032
   97                                                       format_datetime(block.start_dt, timezone=self.event.tzinfo)))
   98                           for block in sorted(blocks, key=attrgetter('full_title', 'start_dt'))]
   99          self.contribution.choices = [('', _('Please select a contribution')), *contrib_choices]
  100          self.block.choices = [('', _('Please select a session block')), *block_choices]
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/vc/forms.py:98` and, if so, apply the standard mitigation for CWE-606.

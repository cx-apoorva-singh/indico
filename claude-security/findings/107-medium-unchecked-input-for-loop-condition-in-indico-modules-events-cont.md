# Unchecked Input for Loop Condition in indico/modules/events/contributions/controllers/management.py:162

| Field | Value |
|---|---|
| ID | `VG-0254` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/events/contributions/controllers/management.py:162`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/events/contributions/controllers/management.py#L162). Engine message: `Unchecked_Input_for_Loop_Condition: form at indico/modules/events/contributions/controllers/management.py:162 reaches getlist at indico/modules/events/contributions/controllers/management.py:162`.

```py
  160      def _process_args(self):
  161          RHManageContributionBase._process_args(self)
  162          ids = {int(x) for x in request.form.getlist('subcontribution_id')}
  163          self.subcontribs = (SubContribution.query
  164                              .with_parent(self.contrib)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/events/contributions/controllers/management.py:162` and, if so, apply the standard mitigation for CWE-606.

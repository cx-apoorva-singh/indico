# Unchecked Input for Loop Condition in indico/core/db/sqlalchemy/util/queries.py:60

| Field | Value |
|---|---|
| ID | `VG-0212` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/core/db/sqlalchemy/util/queries.py:60`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/db/sqlalchemy/util/queries.py#L60). Engine message: `Unchecked_Input_for_Loop_Condition: args at indico/modules/categories/controllers/display.py:168 reaches split at indico/core/db/sqlalchemy/util/queries.py:60`.

```py
   58  
   59  def preprocess_ts_string(text, prefix=True):
   60      atoms = [TS_REGEX.sub(r'\\\1', atom.strip()) for atom in text.split()]
   61      return ' & '.join(f'{atom}:*' if prefix else atom for atom in atoms)
   62  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/db/sqlalchemy/util/queries.py:60` and, if so, apply the standard mitigation for CWE-606.

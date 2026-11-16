# Deserialization of Untrusted Data in indico/core/emails.py:147

| Field | Value |
|---|---|
| ID | `VG-0046` |
| Severity | **High** |
| Status | open |
| CWE | CWE-502 |
| Rule | `Python_Deserialization_of_Untrusted_Data` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Deserialization_of_Untrusted_Data` (CWE-502) reports an issue at [`indico/core/emails.py:147`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/core/emails.py#L147). Engine message: `Deserialization_of_Untrusted_Data: f at indico/core/emails.py:146 reaches load at indico/core/emails.py:147`.

```py
  145      from indico.modules.logs import EventLogEntry
  146      with open(path, 'rb') as f:
  147          email, log_entry_id = pickle.load(f)  # noqa: S301
  148      log_entry = EventLogEntry.get(log_entry_id) if log_entry_id is not None else None
  149      do_send_email(email, log_entry)
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/core/emails.py:147` and, if so, apply the standard mitigation for CWE-502.

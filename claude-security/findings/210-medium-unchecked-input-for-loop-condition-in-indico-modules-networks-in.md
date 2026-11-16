# Unchecked Input for Loop Condition in indico/modules/networks/__init__.py:36

| Field | Value |
|---|---|
| ID | `VG-0357` |
| Severity | **Medium** |
| Status | open |
| CWE | CWE-606 |
| Rule | `Python_Unchecked_Input_for_Loop_Condition` |
| Engine | Vigil CXQL (SAST) |
| Project | Indico 3.3.7 |

## Description

Vigil CXQL rule `Python_Unchecked_Input_for_Loop_Condition` (CWE-606) reports an issue at [`indico/modules/networks/__init__.py:36`](https://github.com/cx-apoorva-singh/indico/blob/a74365c23645b42f9820efecd2b5aac8b0dda4d2/indico/modules/networks/__init__.py#L36). Engine message: `Unchecked_Input_for_Loop_Condition: all at indico/modules/networks/__init__.py:42 reaches _get_attachment_access_networks at indico/modules/networks/__init__.py:36`.

```py
   34          return
   35      ip = str(request.remote_addr)
   36      if any(net.contains_ip(ip) for net in _get_attachment_access_networks()):
   37          return True
   38  
```

## Assessment

Raw SAST engine finding, imported from the "Vigil" sheet of `SAST_Engine_Comparison_Vigil-CXQL 2.xlsx` (confidence=0.0; evidence_tier=unexamined; suppressed=N). It has not been triaged: exploitability and reachability are unverified.

## Recommendation

Verify that attacker-controlled data reaches `indico/modules/networks/__init__.py:36` and, if so, apply the standard mitigation for CWE-606.

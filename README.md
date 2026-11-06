# AuthScope

[Español](README.es.md)

Read-only PowerShell audit of **NTLM usage** and **Kerberos RC4 failures** across every domain controller of an Active Directory domain. One command, one self-contained HTML report with a traffic-light status, what is affected and how to fix it.

NTLM is the basis of relay and pass-the-hash attacks, and Microsoft plans to disable it by default in future Windows Server releases. AuthScope tells you who still uses it, from which machine, against which server, before you block it.

## What it checks
| Check | Source |
|---|---|
| NTLM authentications per account, client and target server, merged across all DCs | `Microsoft-Windows-NTLM/Operational` 8004 |
| Enhanced NTLM logging: NTLM to the DC and forwarded by the DC, with NTLM version (replaces 8004/4776 on that DC) | `Microsoft-Windows-NTLM/Operational` 4022/4023, 4030-4033 |
| NTLMv1 in use | `NtlmVersion` field of the enhanced events |
| NTLM credential validations (fallback when 8004 auditing is off) | Security 4776 |
| NTLM auditing disabled on a DC (the report would look empty) | `AuditNTLMInDomain` |
| DC still accepts NTLMv1 / LM | `LmCompatibilityLevel` |
| Kerberos RC4 / missing AES key failures | System, KDC events 201-209 |

It never writes to AD or to the DCs.

## Usage
```powershell
Install-Module AuthScope -Scope CurrentUser
Invoke-AuthScope -Days 14 -OutputPath C:\Reports
```
Requirements: Windows PowerShell 5.1 or PowerShell 7, WinRM to each DC, and rights to read the Security log (Domain Admins or equivalent). Without `-ComputerName` it audits every DC of the current domain.

Output: `AuthScope-<date>.html`, `.json` (all data) and `-findings.csv`.

## Enable NTLM auditing first
Windows Server 2025 and updated 2019/2022 DCs (KB5064479) already have enhanced NTLM logging. Elsewhere, on the Domain Controllers GPO: *Network security: Restrict NTLM: Audit NTLM authentication in this domain* = **Enable all**. Let it run a few days, then run AuthScope.

## Development
```powershell
Invoke-Pester -Path tests
Invoke-ScriptAnalyzer -Path AuthScope -Recurse
```

## License
AGPL-3.0. See [LICENSE](LICENSE).

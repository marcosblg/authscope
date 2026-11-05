Set-StrictMode -Version Latest

$script:Severities = @('Critical', 'Warning', 'Info')

# Runs on each DC through Invoke-Command: only reads registry and event logs.
$script:DcCollector = {
    param([int]$Days, [int]$MaxEvents)
    $since = (Get-Date).AddDays(-$Days)
    $errors = New-Object System.Collections.ArrayList

    function Get-Reg($Path, $Name) {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($item) { $item.$Name } else { $null }
    }

    function Get-Ev($Filter, $Max) {
        try {
            foreach ($e in Get-WinEvent -FilterHashtable $Filter -MaxEvents $Max -ErrorAction Stop) {
                $data = @{}
                foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $data[[string]$n.Name] = [string]$n.'#text' }
                [pscustomobject]@{ Id = $e.Id; Time = $e.TimeCreated; Provider = $e.ProviderName; Data = $data; Message = $e.Message }
            }
        } catch {
            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { [void]$errors.Add("$($Filter.LogName): $($_.Exception.Message)") }
        }
    }

    $ntlm = @(Get-Ev @{ LogName = 'Microsoft-Windows-NTLM/Operational'; Id = 8004; StartTime = $since } $MaxEvents)
    $cred = @(Get-Ev @{ LogName = 'Security'; Id = 4776; StartTime = $since } $MaxEvents)
    $kdc = @(Get-Ev @{ LogName = 'System'; Id = 201..209; StartTime = $since } $MaxEvents |
            Where-Object { $_.Provider -match 'Kerberos-Key-Distribution|Kdc' })

    [pscustomobject]@{
        AuditNTLMInDomain    = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'AuditNTLMInDomain'
        LmCompatibilityLevel = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
        NtlmEvents           = $ntlm
        CredentialEvents     = $cred
        KdcEvents            = $kdc
        Errors               = $errors
    }
}

function Get-ASDomainController {
    [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | ForEach-Object { $_.Name }
}

function Get-ASDcData {
    param([string[]]$ComputerName, [int]$Days, [int]$MaxEvents)
    foreach ($dc in $ComputerName) {
        try {
            $r = Invoke-Command -ComputerName $dc -ScriptBlock $script:DcCollector -ArgumentList $Days, $MaxEvents -ErrorAction Stop
            [pscustomobject]@{
                Server               = $dc
                Reachable            = $true
                AuditNTLMInDomain    = $r.AuditNTLMInDomain
                LmCompatibilityLevel = $r.LmCompatibilityLevel
                NtlmEvents           = @($r.NtlmEvents)
                CredentialEvents     = @($r.CredentialEvents)
                KdcEvents            = @($r.KdcEvents)
                Errors               = @($r.Errors)
            }
        } catch {
            [pscustomobject]@{
                Server = $dc; Reachable = $false; AuditNTLMInDomain = $null; LmCompatibilityLevel = $null
                NtlmEvents = @(); CredentialEvents = @(); KdcEvents = @(); Errors = @($_.Exception.Message)
            }
        }
    }
}

function Get-ASNtlmUsage {
    # One row per account + client + target server, merged across all DCs.
    param([object[]]$DcData)
    $rows = foreach ($dc in $DcData) {
        foreach ($e in $dc.NtlmEvents) {
            [pscustomobject]@{ Source = '8004'; Dc = $dc.Server; Time = $e.Time
                User = "$($e.Data['DomainName'])\$($e.Data['UserName'])"; Client = $e.Data['WorkstationName']; Target = $e.Data['SChannelName'] }
        }
        foreach ($e in $dc.CredentialEvents) {
            [pscustomobject]@{ Source = '4776'; Dc = $dc.Server; Time = $e.Time
                User = $e.Data['TargetUserName']; Client = $e.Data['Workstation']; Target = '' }
        }
    }
    @($rows) | Where-Object { $_ } | Group-Object Source, User, Client, Target | ForEach-Object {
        $first = $_.Group[0]
        $times = @($_.Group | ForEach-Object { [datetime]$_.Time } | Sort-Object)
        [pscustomobject]@{
            Source = $first.Source; User = $first.User; Client = $first.Client; Target = $first.Target
            Count = $_.Count; FirstSeen = $times[0]; LastSeen = $times[-1]
            Dcs = (($_.Group | ForEach-Object Dc | Sort-Object -Unique) -join ', ')
        }
    } | Sort-Object Count -Descending
}

function New-ASFinding {
    # Only builds an object, changes nothing.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
    param($Severity, $Category, $Server, $Title, $Detail, $Fix)
    [pscustomobject]@{ Severity = $Severity; Category = $Category; Server = $Server; Title = $Title; Detail = $Detail; Fix = $Fix }
}

function Get-ASFinding {
    param([object[]]$DcData, [object[]]$NtlmUsage)
    foreach ($dc in $DcData) {
        if (-not $dc.Reachable) {
            New-ASFinding 'Warning' 'Collection' $dc.Server 'DC not reachable' ($dc.Errors -join '; ') `
                'Check WinRM (Test-WSMan) and that the account running AuthScope can read the Security log on the DC.'
            continue
        }
        foreach ($err in $dc.Errors) {
            New-ASFinding 'Warning' 'Collection' $dc.Server 'Event log could not be read' $err 'Run as a member of Event Log Readers (Security log needs Domain Admins or equivalent).'
        }
        if (-not $dc.AuditNTLMInDomain) {
            New-ASFinding 'Warning' 'Config' $dc.Server 'NTLM auditing is off: report is incomplete' `
                'Event 8004 is not logged, so NTLM usage on this DC is invisible (only 4776, without target server).' `
                "GPO on Domain Controllers: 'Network security: Restrict NTLM: Audit NTLM authentication in this domain' = Enable all."
        }
        # Missing value behaves as 3: the DC still accepts NTLMv1/LM responses.
        $lm = if ($null -eq $dc.LmCompatibilityLevel) { 3 } else { [int]$dc.LmCompatibilityLevel }
        if ($lm -lt 5) {
            New-ASFinding 'Warning' 'Config' $dc.Server "DC accepts NTLMv1 (LmCompatibilityLevel = $lm)" `
                'NTLMv1 responses can be cracked or relayed; they give attackers domain credentials.' `
                "Audit NTLMv1 first (4624 with 'NTLM V1'), then GPO 'Network security: LAN Manager authentication level' = Send NTLMv2 response only. Refuse LM & NTLM."
        }
        $dc.KdcEvents | Group-Object Id | ForEach-Object {
            $msg = [string]$_.Group[0].Message
            New-ASFinding 'Critical' 'RC4' $dc.Server "Kerberos KDC event $($_.Name) x$($_.Count)" $msg.Substring(0, [math]::Min(400, $msg.Length)) `
                'The account or service in the event lacks AES. Set msDS-SupportedEncryptionTypes = 0x18 (AES only) and reset its password so it gets AES keys; check with Microsoft List-AccountKeys.ps1.'
        }
    }
    $NtlmUsage | Group-Object { if ($_.Target) { $_.Target } else { '(unknown: event 4776)' } } | ForEach-Object {
        $count = ($_.Group | Measure-Object Count -Sum).Sum
        $clients = @($_.Group | ForEach-Object Client | Sort-Object -Unique)
        $fix = if ($_.Group[0].Target) {
            "Make clients reach $($_.Name) by FQDN (not IP/alias) and check its SPN: setspn -Q */$($_.Name)*. Apps that only speak NTLM go in 'Restrict NTLM: Add server exceptions in this domain' before blocking."
        } else { 'Enable NTLM auditing (event 8004) to see which server each client is reaching.' }
        New-ASFinding 'Info' 'NTLM' $_.Name "$count NTLM authentications from $($clients.Count) clients" `
            ("Clients: " + (($clients | Select-Object -First 10) -join ', ')) $fix
    }
}

function Get-ASStatus([object[]]$Findings) {
    foreach ($s in $script:Severities) { if ($Findings | Where-Object Severity -EQ $s) { return $s } }
    'OK'
}

function ConvertTo-ASHtml {
    param($Result)
    function E($v) { [System.Net.WebUtility]::HtmlEncode([string]$v) }
    $color = @{ Critical = '#c62828'; Warning = '#ef8f00'; Info = '#1565c0'; OK = '#2e7d32' }
    $sb = New-Object System.Text.StringBuilder
    $counts = foreach ($s in $script:Severities) { "<span class='pill' style='background:$($color[$s])'>$s $(@($Result.Findings | Where-Object Severity -EQ $s).Count)</span>" }
    [void]$sb.Append(@"
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AuthScope report</title><style>
:root{--bg:#fff;--fg:#1a1a1a;--mut:#666;--line:#ddd}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e8e8e8;--mut:#9a9a9a;--line:#333}}
body{background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,Segoe UI,sans-serif;margin:0 auto;max-width:1200px;padding:16px}
h1{margin:0}.mut{color:var(--mut)}.pill{color:#fff;border-radius:12px;padding:2px 10px;margin-right:6px;display:inline-block}
.status{font-size:20px;font-weight:600;color:#fff;padding:10px 16px;border-radius:8px;margin:12px 0}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;margin:8px 0 24px}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{font-size:12px;text-transform:uppercase;color:var(--mut)}
</style></head><body>
<h1>AuthScope</h1><p class="mut">Domain $(E $Result.Domain) &middot; $(E $Result.Generated) &middot; last $(E $Result.Days) days &middot; DCs: $(E ($Result.DomainControllers -join ', '))</p>
<div class="status" style="background:$($color[$Result.Status])">Status: $(E $Result.Status)</div><p>$($counts -join '')</p>
"@)
    $table = {
        param($Title, $Rows, $Cols)
        [void]$sb.Append("<h2>$(E $Title)</h2>")
        if (-not @($Rows).Count) { [void]$sb.Append("<p class='mut'>Nothing found.</p>"); return }
        [void]$sb.Append("<div class='wrap'><table><tr>" + (($Cols | ForEach-Object { "<th>$(E $_)</th>" }) -join '') + '</tr>')
        foreach ($r in $Rows) { [void]$sb.Append('<tr>' + (($Cols | ForEach-Object { "<td>$(E $r.$_)</td>" }) -join '') + '</tr>') }
        [void]$sb.Append('</table></div>')
    }
    & $table 'Findings' $Result.Findings 'Severity', 'Category', 'Server', 'Title', 'Detail', 'Fix'
    & $table 'NTLM usage (top 200)' ($Result.NtlmUsage | Select-Object -First 200) 'User', 'Client', 'Target', 'Count', 'LastSeen', 'Source', 'Dcs'
    & $table 'Domain controllers' $Result.DcSummary 'Server', 'Reachable', 'AuditNTLMInDomain', 'LmCompatibilityLevel', 'NtlmEvents', 'CredentialEvents', 'KdcEvents'
    [void]$sb.Append("<p class='mut'>Read-only audit. Generated by AuthScope.</p></body></html>")
    $sb.ToString()
}

function Invoke-AuthScope {
    <#
    .SYNOPSIS
    Read-only audit of NTLM usage and Kerberos RC4 failures across all domain controllers.
    .DESCRIPTION
    Connects to each DC with WinRM, reads NTLM (8004), credential validation (4776) and KDC (201-209)
    events plus NTLM-related registry settings, and writes an HTML report, JSON and a CSV of findings.
    .EXAMPLE
    Invoke-AuthScope -Days 14 -OutputPath C:\Reports
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,
        [ValidateRange(1, 365)][int]$Days = 7,
        # shortcut: caps events per log per DC, raise it or aggregate remotely if big domains hit the cap.
        [ValidateRange(1, 1000000)][int]$MaxEvents = 20000,
        [string]$OutputPath = (Get-Location).Path
    )
    if (-not $ComputerName) { $ComputerName = @(Get-ASDomainController) }
    $dcData = @(Get-ASDcData -ComputerName $ComputerName -Days $Days -MaxEvents $MaxEvents)
    $usage = @(Get-ASNtlmUsage -DcData $dcData)
    $findings = @(Get-ASFinding -DcData $dcData -NtlmUsage $usage | Sort-Object { $script:Severities.IndexOf($_.Severity) })
    $result = [pscustomobject]@{
        Domain            = $env:USERDNSDOMAIN
        Generated         = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Days              = $Days
        DomainControllers = $ComputerName
        Status            = Get-ASStatus $findings
        Findings          = $findings
        NtlmUsage         = $usage
        DcSummary         = @($dcData | ForEach-Object {
                [pscustomobject]@{ Server = $_.Server; Reachable = $_.Reachable; AuditNTLMInDomain = $_.AuditNTLMInDomain
                    LmCompatibilityLevel = $_.LmCompatibilityLevel; NtlmEvents = $_.NtlmEvents.Count
                    CredentialEvents = $_.CredentialEvents.Count; KdcEvents = $_.KdcEvents.Count }
            })
    }
    $null = New-Item -ItemType Directory -Force -Path $OutputPath
    $base = Join-Path $OutputPath ("AuthScope-" + (Get-Date -Format 'yyyyMMdd-HHmm'))
    ConvertTo-ASHtml $result | Set-Content -Path "$base.html" -Encoding UTF8
    $result | ConvertTo-Json -Depth 5 | Set-Content -Path "$base.json" -Encoding UTF8
    $findings | Export-Csv -Path "$base-findings.csv" -NoTypeInformation -Encoding UTF8
    Write-Verbose "Report: $base.html"
    $result
}

Export-ModuleMember -Function Invoke-AuthScope

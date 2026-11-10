Set-StrictMode -Version Latest

$script:Severities = @('Critical', 'Warning', 'Info')

# KDC RC4 events (KB5073381): odd/even audit ids become blocking ids once enforcement is on.
$script:KdcClientFix = "Enable AES on the client (GPO 'Network security: Configure encryption types allowed for Kerberos'; non-Windows: update firmware/keytab). If impossible, allow RC4 explicitly in the service account msDS-SupportedEncryptionTypes as a temporary exception."
$script:KdcKeyFix = 'Reset the service account password so it gets AES keys (check with Microsoft List-AccountKeys.ps1), then set msDS-SupportedEncryptionTypes = 0x18.'
$script:KdcEvents = @{
    201 = 'Warning', 'Client offers only RC4 (blocked as 203 under enforcement)', 'Client advertises only RC4 and the service has no msDS-SupportedEncryptionTypes.', $script:KdcClientFix
    202 = 'Warning', 'Service account has no AES keys (blocked as 204 under enforcement)', 'Service account only has RC4/DES keys.', $script:KdcKeyFix
    203 = 'Critical', 'Kerberos blocked: client offers only RC4', 'KDC refused the ticket: client advertises only RC4.', $script:KdcClientFix
    204 = 'Critical', 'Kerberos blocked: service account has no AES keys', 'KDC refused the ticket: service account only has RC4/DES keys.', $script:KdcKeyFix
    205 = 'Warning', 'Domain default allows insecure Kerberos ciphers', 'DefaultDomainSupportedEncTypes on this DC explicitly enables RC4/DES.', 'Remove RC4/DES from HKLM\SYSTEM\CurrentControlSet\Services\KDC\DefaultDomainSupportedEncTypes (or delete it to use the AES default) and restart KDC.'
    206 = 'Warning', 'Client offers only RC4 to an AES-only service (blocked as 208)', 'Service or domain allows only AES but the client advertises only RC4.', $script:KdcClientFix
    207 = 'Warning', 'AES-only service has no AES keys (blocked as 209)', 'Service or domain allows only AES but the service account has no AES keys.', $script:KdcKeyFix
    208 = 'Critical', 'Kerberos blocked: client offers only RC4 to an AES-only service', 'KDC refused the ticket: AES-only configuration and the client advertises only RC4.', $script:KdcClientFix
    209 = 'Critical', 'Kerberos blocked: AES-only service has no AES keys', 'KDC refused the ticket: AES-only configuration and the service account has no AES keys.', $script:KdcKeyFix
}

# Runs on each DC (or member server with -Member) through Invoke-Command: only reads registry and event logs.
$script:DcCollector = {
    param([int]$Days, [int]$MaxEvents, [bool]$Member)
    $since = (Get-Date).AddDays(-$Days)
    $errors = New-Object System.Collections.ArrayList

    function Get-Reg($Path, $Name) {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($item) { $item.$Name } else { $null }
    }

    function Get-Ev($Filter, $Max) {
        try {
            $p = if ($Filter.ContainsKey('XPath')) { @{ LogName = $Filter.LogName; FilterXPath = $Filter.XPath } } else { @{ FilterHashtable = $Filter } }
            foreach ($e in Get-WinEvent @p -MaxEvents $Max -ErrorAction Stop) {
                $data = @{}
                foreach ($n in ([xml]$e.ToXml()).Event.EventData.Data) { $data[[string]$n.Name] = [string]$n.'#text' }
                [pscustomobject]@{ Id = $e.Id; Time = $e.TimeCreated; Provider = $e.ProviderName; Data = $data; Message = $e.Message }
            }
        } catch {
            if ($_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { [void]$errors.Add("$($Filter.LogName): $($_.Exception.Message)") }
        }
    }

    # Member servers: 8001 = outgoing NTLM from this server, 8002/8003 = incoming NTLM to it (Restrict NTLM audit GPOs),
    # 4022/4023 = incoming NTLM with enhanced logging (any server, no GPO needed; verified on Server 2025).
    if ($Member) {
        return [pscustomobject]@{
            AuditNTLMInDomain = $null; LmCompatibilityLevel = $null; CredentialEvents = @(); LogonEvents = @(); KdcEvents = @(); Errors = $errors
            NtlmEvents = @(Get-Ev @{ LogName = 'Microsoft-Windows-NTLM/Operational'; Id = 8001, 8002, 8003, 4022, 4023; StartTime = $since } $MaxEvents)
        }
    }

    # 4022/4023 (NTLM to this DC) and 4030-4033 (forwarded by this DC) = enhanced NTLM logging, on by default (KB5064479).
    # 8006 = like 8004, for a logon passed through to a trusting domain.
    $ntlm = @(Get-Ev @{ LogName = 'Microsoft-Windows-NTLM/Operational'; Id = 8004, 8006, 4022, 4023, 4030, 4031, 4032, 4033; StartTime = $since } $MaxEvents)
    $cred = @(Get-Ev @{ LogName = 'Security'; Id = 4776; StartTime = $since } $MaxEvents)
    # NTLMv1 logons to this DC, filtered on the DC so the rest of 4624 never leaves it. XPath: PS 5.1 ignores EventData keys in FilterHashtable.
    $ms = [int64]$Days * 86400000
    $logon = @(Get-Ev @{ LogName = 'Security'; XPath = "*[System[EventID=4624 and TimeCreated[timediff(@SystemTime) <= $ms]]] and *[EventData[Data[@Name='LmPackageName']='NTLM V1']]" } $MaxEvents)
    $kdc = @(Get-Ev @{ LogName = 'System'; Id = 201..209; StartTime = $since } $MaxEvents |
            Where-Object { $_.Provider -match 'Kerberos-Key-Distribution|Kdc' })

    [pscustomobject]@{
        AuditNTLMInDomain    = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' 'AuditNTLMInDomain'
        LmCompatibilityLevel = Get-Reg 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' 'LmCompatibilityLevel'
        NtlmEvents           = $ntlm
        CredentialEvents     = $cred
        LogonEvents          = $logon
        KdcEvents            = $kdc
        Errors               = $errors
    }
}

function Get-ASDomainController {
    [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers | ForEach-Object { $_.Name }
}

function Get-ASDcData {
    param([string[]]$ComputerName, [int]$Days, [int]$MaxEvents, [switch]$Member)
    $role = if ($Member) { 'Member' } else { 'DC' }
    foreach ($dc in $ComputerName) {
        try {
            $r = Invoke-Command -ComputerName $dc -ScriptBlock $script:DcCollector -ArgumentList $Days, $MaxEvents, $Member.IsPresent -ErrorAction Stop
            [pscustomobject]@{
                Server               = $dc
                Role                 = $role
                Reachable            = $true
                AuditNTLMInDomain    = $r.AuditNTLMInDomain
                LmCompatibilityLevel = $r.LmCompatibilityLevel
                NtlmEvents           = @($r.NtlmEvents)
                CredentialEvents     = @($r.CredentialEvents)
                LogonEvents          = @($r.LogonEvents)
                KdcEvents            = @($r.KdcEvents)
                Errors               = @($r.Errors)
            }
        } catch {
            [pscustomobject]@{
                Server = $dc; Role = $role; Reachable = $false; AuditNTLMInDomain = $null; LmCompatibilityLevel = $null
                NtlmEvents = @(); CredentialEvents = @(); LogonEvents = @(); KdcEvents = @(); Errors = @($_.Exception.Message)
            }
        }
    }
}

function Get-ASNtlmUsage {
    # One row per account + client + target server, merged across all DCs.
    param([object[]]$DcData)
    $rows = foreach ($dc in $DcData) {
        # shortcut: a server with enhanced events also logs every one as 8004/8006/4776 (DC) or 8002/8003 (member), so those are skipped for the whole window; mixed windows (patched mid-window) lose the older ones.
        $enhanced = @($dc.NtlmEvents | Where-Object { $_.Id -in 4022, 4023, 4030, 4031, 4032, 4033 }).Count -gt 0
        foreach ($e in $dc.NtlmEvents) {
            $d = $e.Data
            switch ($e.Id) {
                { $_ -in 8004, 8006 } { if (-not $enhanced) { [pscustomobject]@{ Source = "$($e.Id)"; Dc = $dc.Server; Time = $e.Time; Version = ''
                            User = "$($d['DomainName'])\$($d['UserName'])"; Client = $d['WorkstationName']; Target = $d['SChannelName'] } } }
                { $_ -in 4022, 4023 } { [pscustomobject]@{ Source = "$($e.Id)"; Dc = $dc.Server; Time = $e.Time; Version = $d['NtlmVersion']
                        # Real 4022 can carry a UPN in Username and the literal 'Null' in DomainName.
                        User = if ($d['DomainName'] -in '', 'Null' -or $d['Username'] -match '@') { $d['Username'] } else { "$($d['DomainName'])\$($d['Username'])" }
                        Client = "$($d['RemoteClientMachine']) ($($d['ClientIP']))"; Target = $dc.Server } }
                # shortcut: one NTLM logon to a member can show as 8004 on the DC plus 8003 on the member (and 8001 on the caller), so per-target counts add up; dedupe by time/user if it misleads.
                8001 { [pscustomobject]@{ Source = '8001'; Dc = $dc.Server; Time = $e.Time; Version = ''
                        User = "$($d['DomainName'])\$($d['UserName'])"; Client = "$($dc.Server) ($($d['ProcessName']))"; Target = $d['TargetName'] } }
                # 8002 has no remote user or client: ClientUserName is the local server account (TEKU-DC$ in a real event).
                8002 { if (-not $enhanced) { [pscustomobject]@{ Source = '8002'; Dc = $dc.Server; Time = $e.Time; Version = ''
                        User = ''; Client = "(unknown, process $($d['ProcessName']))"; Target = $dc.Server } } }
                8003 { if (-not $enhanced) { [pscustomobject]@{ Source = '8003'; Dc = $dc.Server; Time = $e.Time; Version = ''
                        User = "$($d['DomainName'])\$($d['UserName'])"; Client = $d['Workstation']; Target = $dc.Server } } }
                { $_ -in 4030..4033 } { [pscustomobject]@{ Source = "$($e.Id)"; Dc = $dc.Server; Time = $e.Time; Version = $d['NtlmVersion']
                        User = "$($d['AccountDomain'])\$($d['AccountName'])"; Client = $d['AccountMachine']; Target = $d['ServerName'] } }
            }
        }
        if (-not $enhanced) {
            foreach ($e in $dc.CredentialEvents) {
                [pscustomobject]@{ Source = '4776'; Dc = $dc.Server; Time = $e.Time; Version = ''
                    User = $e.Data['TargetUserName']; Client = $e.Data['Workstation']; Target = '' }
            }
            # Without enhanced logging (2016, unpatched 2019/2022) 4624 is the only NTLMv1 evidence; with it, 4022 already counts these.
            foreach ($e in $dc.LogonEvents) {
                [pscustomobject]@{ Source = '4624'; Dc = $dc.Server; Time = $e.Time; Version = 'NTLMv1'
                    User = "$($e.Data['TargetDomainName'])\$($e.Data['TargetUserName'])"; Client = "$($e.Data['WorkstationName']) ($($e.Data['IpAddress']))"; Target = $dc.Server }
            }
        }
    }
    @($rows) | Where-Object { $_ } | Group-Object Source, User, Client, Target, Version | ForEach-Object {
        $first = $_.Group[0]
        $times = @($_.Group | ForEach-Object { [datetime]$_.Time } | Sort-Object)
        [pscustomobject]@{
            Source = $first.Source; User = $first.User; Client = $first.Client; Target = $first.Target; Version = $first.Version
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
        if ($dc.Role -eq 'Member') {
            if (-not @($dc.NtlmEvents).Count) {
                New-ASFinding 'Warning' 'Config' $dc.Server 'No NTLM audit events on member server' `
                    'Events 8001-8003 and 4022/4023 are not logged (auditing off and no enhanced NTLM logging, or no NTLM in the window).' `
                    "GPO on member servers: 'Network security: Restrict NTLM: Audit Incoming NTLM Traffic' = Enable auditing for all accounts and 'Restrict NTLM: Outgoing NTLM traffic to remote servers' = Audit all."
            }
            # Missing value = 3 on supported Windows: only an explicit value below 3 sends NTLMv1/LM.
            if ($null -ne $dc.LmCompatibilityLevel -and [int]$dc.LmCompatibilityLevel -lt 3) {
                New-ASFinding 'Warning' 'Config' $dc.Server "Server sends NTLMv1 (LmCompatibilityLevel = $($dc.LmCompatibilityLevel))" `
                    'When this server authenticates to others it may send LM/NTLMv1 responses, which can be cracked or relayed.' `
                    "GPO on member servers: 'Network security: LAN Manager authentication level' = Send NTLMv2 response only (LmCompatibilityLevel >= 3)."
            }
            continue
        }
        if (-not $dc.AuditNTLMInDomain -and -not @($dc.NtlmEvents | Where-Object { $_.Id -notin 8004, 8006 }).Count) {
            New-ASFinding 'Warning' 'Config' $dc.Server 'NTLM auditing is off: report is incomplete' `
                'Event 8004 is not logged, so NTLM usage on this DC is invisible (only 4776, without target server).' `
                "GPO on Domain Controllers: 'Network security: Restrict NTLM: Audit NTLM authentication in this domain' = Enable all."
        }
        # Missing value behaves as 3: the DC still accepts NTLMv1/LM responses.
        $lm = if ($null -eq $dc.LmCompatibilityLevel) { 3 } else { [int]$dc.LmCompatibilityLevel }
        if ($lm -lt 5) {
            New-ASFinding 'Warning' 'Config' $dc.Server "DC accepts NTLMv1 (LmCompatibilityLevel = $lm)" `
                'NTLMv1 responses can be cracked or relayed; they give attackers domain credentials.' `
                "Check who still uses NTLMv1 first (NTLMv1 rows in NTLM usage, from enhanced events 4022/4023 or Security 4624), then GPO 'Network security: LAN Manager authentication level' = Send NTLMv2 response only. Refuse LM & NTLM."
        }
        $dc.KdcEvents | Group-Object Id | ForEach-Object {
            $k = $script:KdcEvents[[int]$_.Name]
            if (-not $k) {
                $msg = [string]$_.Group[0].Message
                $k = 'Critical', "Kerberos KDC event $($_.Name)", $msg.Substring(0, [math]::Min(400, $msg.Length)), $script:KdcKeyFix
            }
            $who = if ([int]$_.Name -eq 205) { "DefaultDomainSupportedEncTypes = $($_.Group[0].Data['DDSET'])" } else {
                $pairs = @($_.Group | ForEach-Object { "$($_.Data['AccountName']) -> $($_.Data['ServiceName']) ($($_.Data['IpAddress']))" } | Sort-Object -Unique)
                "$($pairs.Count) account/service pairs: " + (($pairs | Select-Object -First 10) -join '; ')
            }
            New-ASFinding $k[0] 'RC4' $dc.Server "$($k[1]) (event $($_.Name) x$($_.Count))" "$($k[2]) $who" $k[3]
        }
    }
    $v1 = @($NtlmUsage | Where-Object { $_.Version -match 'v1' })
    if ($v1) {
        New-ASFinding 'Critical' 'NTLM' (($v1.Target | Sort-Object -Unique) -join ', ') "NTLMv1 in use: $(($v1 | Measure-Object Count -Sum).Sum) authentications" `
            ("User / client: " + ((@($v1 | ForEach-Object { "$($_.User) / $($_.Client)" } | Sort-Object -Unique) | Select-Object -First 10) -join '; ')) `
            'Move these clients to NTLMv2 (LmCompatibilityLevel >= 3 on the client, or update the device), then set LAN Manager authentication level = Send NTLMv2 response only. Refuse LM & NTLM on the DCs.'
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
    & $table 'NTLM usage (top 200)' ($Result.NtlmUsage | Select-Object -First 200) 'User', 'Client', 'Target', 'Version', 'Count', 'LastSeen', 'Source', 'Dcs'
    & $table 'Servers' $Result.DcSummary 'Server', 'Role', 'Reachable', 'AuditNTLMInDomain', 'LmCompatibilityLevel', 'NtlmEvents', 'CredentialEvents', 'LogonEvents', 'KdcEvents'
    [void]$sb.Append("<p class='mut'>Read-only audit. Generated by AuthScope.</p></body></html>")
    $sb.ToString()
}

function Invoke-AuthScope {
    <#
    .SYNOPSIS
    Read-only audit of NTLM usage and Kerberos RC4 failures across all domain controllers.
    .DESCRIPTION
    Connects to each DC with WinRM, reads NTLM (8004, 4022/4023, 4030-4033), credential validation (4776),
    NTLMv1 logons (4624) and KDC (201-209)
    events plus NTLM-related registry settings, and writes an HTML report, JSON and a CSV of findings.
    With -MemberServer it also reads NTLM events 8001-8003 and 4022/4023 on those servers.
    .EXAMPLE
    Invoke-AuthScope -Days 14 -OutputPath C:\Reports
    .EXAMPLE
    Invoke-AuthScope -MemberServer FS1, SQL1
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName,
        # Optional: member servers to read 8001-8003/4022-4023 from (NTLM seen at the server itself; 8001-8003 need the Restrict NTLM audit GPOs).
        [string[]]$MemberServer,
        [ValidateRange(1, 365)][int]$Days = 7,
        # shortcut: caps events per log per DC, raise it or aggregate remotely if big domains hit the cap.
        [ValidateRange(1, 1000000)][int]$MaxEvents = 20000,
        [string]$OutputPath = (Get-Location).Path
    )
    if (-not $ComputerName) { $ComputerName = @(Get-ASDomainController) }
    $dcData = @(Get-ASDcData -ComputerName $ComputerName -Days $Days -MaxEvents $MaxEvents)
    if ($MemberServer) { $dcData += @(Get-ASDcData -ComputerName $MemberServer -Days $Days -MaxEvents $MaxEvents -Member) }
    $usage = @(Get-ASNtlmUsage -DcData $dcData)
    $findings = @(Get-ASFinding -DcData $dcData -NtlmUsage $usage | Sort-Object { $script:Severities.IndexOf($_.Severity) })
    $result = [pscustomobject]@{
        Domain            = $env:USERDNSDOMAIN
        Generated         = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        Days              = $Days
        DomainControllers = $ComputerName
        MemberServers     = @($MemberServer)
        Status            = Get-ASStatus $findings
        Findings          = $findings
        NtlmUsage         = $usage
        DcSummary         = @($dcData | ForEach-Object {
                [pscustomobject]@{ Server = $_.Server; Role = $_.Role; Reachable = $_.Reachable; AuditNTLMInDomain = $_.AuditNTLMInDomain
                    LmCompatibilityLevel = $_.LmCompatibilityLevel; NtlmEvents = $_.NtlmEvents.Count
                    CredentialEvents = $_.CredentialEvents.Count; LogonEvents = $_.LogonEvents.Count; KdcEvents = $_.KdcEvents.Count }
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

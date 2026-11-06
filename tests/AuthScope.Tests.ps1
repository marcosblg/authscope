BeforeAll {
    Import-Module "$PSScriptRoot\..\AuthScope\AuthScope.psd1" -Force

    function New-Dc {
        param($Server = 'DC1', $Audit = 7, $Lm = 5, $Ntlm = @(), $Cred = @(), $Logon = @(), $Kdc = @(), $Reachable = $true, $Role = 'DC')
        [pscustomobject]@{ Server = $Server; Role = $Role; Reachable = $Reachable; AuditNTLMInDomain = $Audit; LmCompatibilityLevel = $Lm
            NtlmEvents = $Ntlm; CredentialEvents = $Cred; LogonEvents = $Logon; KdcEvents = $Kdc; Errors = @() }
    }
    function New-8004($User, $Client, $Target, $Time = '2026-11-01') {
        [pscustomobject]@{ Id = 8004; Time = [datetime]$Time; Data = @{ DomainName = 'LAB'; UserName = $User; WorkstationName = $Client; SChannelName = $Target } }
    }
}

Describe 'Get-ASNtlmUsage' {
    It 'merges the same user/client/target across DCs' {
        InModuleScope AuthScope -Parameters @{ a = (New-Dc -Server DC1 -Ntlm @((New-8004 svc PC1 FS1 '2026-11-01'), (New-8004 svc PC1 FS1 '2026-11-03')))
            b = (New-Dc -Server DC2 -Ntlm @((New-8004 svc PC1 FS1 '2026-11-02'), (New-8004 bob PC2 FS1))) } {
            $u = @(Get-ASNtlmUsage -DcData @($a, $b))
            $u.Count | Should -Be 2
            $u[0].User | Should -Be 'LAB\svc'
            $u[0].Count | Should -Be 3
            $u[0].Dcs | Should -Be 'DC1, DC2'
            $u[0].LastSeen | Should -Be ([datetime]'2026-11-03')
        }
    }
    It 'uses enhanced events (4022/4032) with NTLM version and skips 8004/4776 on that DC' {
        $e4022 = [pscustomobject]@{ Id = 4022; Time = [datetime]'2026-11-01'; Data = @{ DomainName = 'LAB'; Username = 'bob'; RemoteClientMachine = 'PC2'; ClientIP = '10.0.0.2'; NtlmVersion = 'NTLMv1' } }
        $e4032 = [pscustomobject]@{ Id = 4032; Time = [datetime]'2026-11-01'; Data = @{ AccountDomain = 'LAB'; AccountName = 'svc'; AccountMachine = 'PC1'; ServerName = 'FS1'; NtlmVersion = 'NTLMv2' } }
        $cred = [pscustomobject]@{ Id = 4776; Time = [datetime]'2026-11-01'; Data = @{ TargetUserName = 'x'; Workstation = 'PC9' } }
        InModuleScope AuthScope -Parameters @{ dc = (New-Dc -Ntlm @($e4022, $e4032, (New-8004 old PC3 FS2)) -Cred @($cred)) } {
            $u = @(Get-ASNtlmUsage -DcData @($dc))
            $u.Count | Should -Be 2
            ($u | Where-Object User -eq 'LAB\bob').Client | Should -Be 'PC2 (10.0.0.2)'
            ($u | Where-Object User -eq 'LAB\bob').Version | Should -Be 'NTLMv1'
            ($u | Where-Object User -eq 'LAB\svc').Target | Should -Be 'FS1'
            $f = @(Get-ASFinding -DcData @($dc) -NtlmUsage $u)
            ($f | Where-Object Title -like 'NTLMv1 in use*').Severity | Should -Be 'Critical'
            $f.Title | Should -Not -Contain 'NTLM auditing is off: report is incomplete'
        }
    }
    It 'reports NTLMv1 from 4624 only on DCs without enhanced logging' {
        $logon = [pscustomobject]@{ Id = 4624; Time = [datetime]'2026-11-01'; Data = @{ TargetDomainName = 'LAB'; TargetUserName = 'scan'; WorkstationName = 'MFP1'; IpAddress = '10.0.0.9'; LmPackageName = 'NTLM V1' } }
        $e4022 = [pscustomobject]@{ Id = 4022; Time = [datetime]'2026-11-01'; Data = @{ DomainName = 'LAB'; Username = 'scan'; RemoteClientMachine = 'MFP1'; ClientIP = '10.0.0.9'; NtlmVersion = 'NTLMv1' } }
        InModuleScope AuthScope -Parameters @{ old = (New-Dc -Server DC16 -Logon @($logon, $logon)); new = (New-Dc -Server DC25 -Ntlm @($e4022) -Logon @($logon)) } {
            $u = @(Get-ASNtlmUsage -DcData @($old))
            $u.Count | Should -Be 1
            $u[0].Source | Should -Be '4624'
            $u[0].User | Should -Be 'LAB\scan'
            $u[0].Client | Should -Be 'MFP1 (10.0.0.9)'
            $u[0].Target | Should -Be 'DC16'
            $u[0].Count | Should -Be 2
            (@(Get-ASFinding -DcData @($old) -NtlmUsage $u) | Where-Object Title -like 'NTLMv1 in use*').Title | Should -Be 'NTLMv1 in use: 2 authentications'
            @(Get-ASNtlmUsage -DcData @($new)).Source | Should -Be '4022'
        }
    }
    It 'reads member server events 8001-8003 and skips DC-only checks on members' {
        $e8001 = [pscustomobject]@{ Id = 8001; Time = [datetime]'2026-11-01'; Data = @{ TargetName = 'cifs/NAS1'; DomainName = 'LAB'; UserName = 'svc'; ProcessName = 'C:pp.exe' } }
        $e8002 = [pscustomobject]@{ Id = 8002; Time = [datetime]'2026-11-01'; Data = @{ ProcessName = 'C:\Windows\System32\lsass.exe' } }
        $e8003 = [pscustomobject]@{ Id = 8003; Time = [datetime]'2026-11-01'; Data = @{ DomainName = 'LAB'; UserName = 'bob'; Workstation = 'PC2'; ProcessName = 'System' } }
        InModuleScope AuthScope -Parameters @{ fs = (New-Dc -Server FS1 -Role Member -Audit $null -Lm $null -Ntlm @($e8001, $e8002, $e8003)); empty = (New-Dc -Server FS2 -Role Member -Audit $null -Lm $null) } {
            $u = @(Get-ASNtlmUsage -DcData @($fs))
            $u.Count | Should -Be 3
            ($u | Where-Object Source -EQ '8001').Target | Should -Be 'cifs/NAS1'
            ($u | Where-Object Source -EQ '8001').Client | Should -Be 'FS1 (C:pp.exe)'
            ($u | Where-Object Source -EQ '8003').Client | Should -Be 'PC2'
            ($u | Where-Object Source -EQ '8003').Target | Should -Be 'FS1'
            $f = @(Get-ASFinding -DcData @($fs, $empty) -NtlmUsage $u)
            $f.Title | Should -Not -Contain 'NTLM auditing is off: report is incomplete'
            $f.Title | Should -Not -Match 'LmCompatibilityLevel'
            ($f | Where-Object Server -EQ 'FS2').Title | Should -Be 'No NTLM audit events on member server'
        }
    }
    It 'prefers 4022 over 8002/8003 on members and counts 8006 like 8004 (shapes from real TEKU-DC events)' {
        $e4022 = [pscustomobject]@{ Id = 4022; Time = [datetime]'2026-11-06'; Data = @{ Username = 'Administrador@teku.local'; DomainName = 'Null'; RemoteClientMachine = 'APLUSSERVER'; ClientIP = '10.10.33.51'; NtlmVersion = 'NTLMv2' } }
        $e8002 = [pscustomobject]@{ Id = 8002; Time = [datetime]'2026-11-06'; Data = @{ ProcessName = '-'; ClientUserName = 'TEKU-DC$'; ClientDomainName = 'TEKU' } }
        $e8006 = [pscustomobject]@{ Id = 8006; Time = [datetime]'2026-11-06'; Data = @{ SChannelName = 'APLUSSERVER'; UserName = 'administrador'; DomainName = 'TEKU'; WorkstationName = 'DESKTOP-NKPO9QP' } }
        InModuleScope AuthScope -Parameters @{ fs = (New-Dc -Server FS1 -Role Member -Audit $null -Lm $null -Ntlm @($e4022, $e8002)); dc = (New-Dc -Server DC19 -Ntlm @($e8006)) } {
            $u = @(Get-ASNtlmUsage -DcData @($fs))
            $u.Count | Should -Be 1
            $u[0].User | Should -Be 'Administrador@teku.local'
            $u[0].Client | Should -Be 'APLUSSERVER (10.10.33.51)'
            $u[0].Target | Should -Be 'FS1'
            $t = @(Get-ASNtlmUsage -DcData @($dc))
            $t[0].Source | Should -Be '8006'
            $t[0].Target | Should -Be 'APLUSSERVER'
        }
    }
}

Describe 'Get-ASFinding' {
    It 'is clean for a hardened DC with no events' {
        InModuleScope AuthScope -Parameters @{ dc = (New-Dc) } {
            @(Get-ASFinding -DcData @($dc) -NtlmUsage @()).Count | Should -Be 0
        }
    }
    It 'warns when NTLM auditing is off and when LmCompatibilityLevel is missing' {
        InModuleScope AuthScope -Parameters @{ dc = (New-Dc -Audit $null -Lm $null) } {
            $f = @(Get-ASFinding -DcData @($dc) -NtlmUsage @())
            $f.Title | Should -Contain 'NTLM auditing is off: report is incomplete'
            $f.Title | Should -Contain 'DC accepts NTLMv1 (LmCompatibilityLevel = 3)'
        }
    }
    It 'explains KDC RC4 events by id, with affected accounts, blocked ones as Critical' {
        $ev = { param($Id, $Acc) [pscustomobject]@{ Id = $Id; Message = 'm'; Data = @{ AccountName = $Acc; ServiceName = 'svc-sql'; IpAddress = '10.0.0.5'; DDSET = '0x27' } } }
        $kdc = @((& $ev 204 'nas$'), (& $ev 204 'nas$'), (& $ev 201 'pc1$'), (& $ev 205 ''), (& $ev 999 'x'))
        InModuleScope AuthScope -Parameters @{ dc = (New-Dc -Kdc $kdc) } {
            $f = @(Get-ASFinding -DcData @($dc) -NtlmUsage @())
            $f.Count | Should -Be 4
            $blocked = $f | Where-Object Title -Like '*event 204 x2*'
            $blocked.Severity | Should -Be 'Critical'
            $blocked.Detail | Should -Match '1 account/service pairs: nas\$ -> svc-sql \(10.0.0.5\)'
            ($f | Where-Object Title -Like '*event 201*').Severity | Should -Be 'Warning'
            ($f | Where-Object Title -Like '*event 205*').Detail | Should -Match 'DefaultDomainSupportedEncTypes = 0x27'
            ($f | Where-Object Title -Like '*event 999*').Severity | Should -Be 'Critical'
        }
    }
    It 'reports an unreachable DC instead of failing' {
        InModuleScope AuthScope -Parameters @{ dc = (New-Dc -Reachable $false) } {
            (Get-ASFinding -DcData @($dc) -NtlmUsage @()).Title | Should -Be 'DC not reachable'
        }
    }
    It 'creates one NTLM finding per target server' {
        InModuleScope AuthScope -Parameters @{ dc = (New-Dc -Ntlm @((New-8004 a PC1 FS1), (New-8004 b PC2 FS1), (New-8004 a PC1 SQL1))) } {
            $f = @(Get-ASFinding -DcData @($dc) -NtlmUsage @(Get-ASNtlmUsage -DcData @($dc)))
            ($f | Where-Object Server -EQ 'FS1').Title | Should -Be '2 NTLM authentications from 2 clients'
            $f.Count | Should -Be 2
        }
    }
}

Describe 'ConvertTo-ASHtml' {
    It 'HTML-encodes data coming from event logs' {
        InModuleScope AuthScope {
            $r = [pscustomobject]@{ Domain = 'lab.local'; Generated = 'now'; Days = 7; DomainControllers = @('DC1'); Status = 'Info'
                Findings = @(New-ASFinding 'Info' 'NTLM' '<script>x</script>' 't' 'd' 'f'); NtlmUsage = @(); DcSummary = @() }
            $html = ConvertTo-ASHtml $r
            $html | Should -Not -Match '<script>'
            $html | Should -Match '&lt;script&gt;'
        }
    }
}

Describe 'Invoke-AuthScope' {
    It 'writes HTML, JSON and CSV and returns the worst status' {
        Mock -ModuleName AuthScope Get-ASDcData { [pscustomobject]@{ Server = 'DC1'; Role = 'DC'; Reachable = $true; AuditNTLMInDomain = 7; LmCompatibilityLevel = 2
                NtlmEvents = @(); CredentialEvents = @(); LogonEvents = @(); KdcEvents = @(); Errors = @() } }
        $r = Invoke-AuthScope -ComputerName DC1 -OutputPath $TestDrive
        $r.Status | Should -Be 'Warning'
        (Get-ChildItem $TestDrive -Filter 'AuthScope-*.html').Count | Should -Be 1
        (Get-ChildItem $TestDrive -Filter 'AuthScope-*.json').Count | Should -Be 1
        (Get-ChildItem $TestDrive -Filter 'AuthScope-*-findings.csv').Count | Should -Be 1
    }
}

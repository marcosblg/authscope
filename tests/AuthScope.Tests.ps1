BeforeAll {
    Import-Module "$PSScriptRoot\..\AuthScope\AuthScope.psd1" -Force

    function New-Dc {
        param($Server = 'DC1', $Audit = 7, $Lm = 5, $Ntlm = @(), $Cred = @(), $Kdc = @(), $Reachable = $true)
        [pscustomobject]@{ Server = $Server; Reachable = $Reachable; AuditNTLMInDomain = $Audit; LmCompatibilityLevel = $Lm
            NtlmEvents = $Ntlm; CredentialEvents = $Cred; KdcEvents = $Kdc; Errors = @() }
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
    It 'marks KDC events as Critical RC4, grouped by event id' {
        $kdc = @(1..3 | ForEach-Object { [pscustomobject]@{ Id = 205; Message = 'no AES key' } })
        InModuleScope AuthScope -Parameters @{ dc = (New-Dc -Kdc $kdc) } {
            $f = @(Get-ASFinding -DcData @($dc) -NtlmUsage @())
            $f.Count | Should -Be 1
            $f[0].Severity | Should -Be 'Critical'
            $f[0].Title | Should -Be 'Kerberos KDC event 205 x3'
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
        Mock -ModuleName AuthScope Get-ASDcData { [pscustomobject]@{ Server = 'DC1'; Reachable = $true; AuditNTLMInDomain = 7; LmCompatibilityLevel = 2
                NtlmEvents = @(); CredentialEvents = @(); KdcEvents = @(); Errors = @() } }
        $r = Invoke-AuthScope -ComputerName DC1 -OutputPath $TestDrive
        $r.Status | Should -Be 'Warning'
        (Get-ChildItem $TestDrive -Filter 'AuthScope-*.html').Count | Should -Be 1
        (Get-ChildItem $TestDrive -Filter 'AuthScope-*.json').Count | Should -Be 1
        (Get-ChildItem $TestDrive -Filter 'AuthScope-*-findings.csv').Count | Should -Be 1
    }
}

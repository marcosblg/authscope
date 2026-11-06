@{
    RootModule        = 'AuthScope.psm1'
    ModuleVersion     = '0.1.1'
    GUID              = '5b8f2d6e-3a41-4c7e-9f0b-7d2e8c1a4b63'
    Author            = 'Marcos'
    Description       = 'Read-only audit of NTLM usage and Kerberos RC4 failures across all Active Directory domain controllers, with a single-file HTML report.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @('Invoke-AuthScope')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('ActiveDirectory', 'NTLM', 'Kerberos', 'RC4', 'Security', 'Audit'); LicenseUri = 'https://www.gnu.org/licenses/agpl-3.0.html'; ProjectUri = 'https://github.com/marcosblg/authscope' } }
}

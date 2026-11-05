# AuthScope

Módulo PowerShell de solo lectura que audita el uso de NTLM (centro del producto) y los fallos de Kerberos RC4 (diagnóstico) en todos los DC de un dominio AD, con informe HTML de un solo archivo. Ángulo de venta: seguridad (relay, pass-the-hash) + preparación para la desactivación de NTLM por defecto (sin fecha oficial).

Familia Scope de marcosblg, primera en PowerShell.

## Mapa
- `AuthScope/AuthScope.psd1` — manifiesto (exporta solo `Invoke-AuthScope`).
- `AuthScope/AuthScope.psm1` — todo el módulo:
  - `$DcCollector`: scriptblock que corre en cada DC por WinRM (registro + eventos 8004, 4776, KDC 201-209).
  - `Get-ASDcData` (recogida), `Get-ASNtlmUsage` (agrega uso NTLM), `Get-ASFinding` (reglas → hallazgos con corrección), `ConvertTo-ASHtml` (informe), `Invoke-AuthScope` (orquesta y escribe HTML/JSON/CSV).
- `tests/AuthScope.Tests.ps1` — Pester 5, con datos falsos (no necesita AD).
- `.github/workflows/ci.yml` — PSScriptAnalyzer + Pester en PS 5.1 y 7.
- `README.md` — inglés. `TRASPASO.md` — estado y siguiente paso.

## Arranque y pruebas
```powershell
Import-Module .\AuthScope\AuthScope.psd1 -Force; Invoke-AuthScope -Days 7 -OutputPath .\out
Invoke-Pester -Path tests
Invoke-ScriptAnalyzer -Path AuthScope -Recurse -Severity Warning,Error
```

## Decisiones
- Solo lectura: nunca modifica AD ni los DC.
- Compatible con Windows PowerShell 5.1 y PowerShell 7. Sin dependencia de RSAT (DC vía System.DirectoryServices).
- Recogida separada del análisis: todo lo que no es `$DcCollector`/`Get-ASDcData` es puro y testeable.
- MVP solo lee DC (8004). Eventos 8001-8003 de servidores miembros: modo opcional futuro.
- No se replica el inventario de `msDS-SupportedEncryptionTypes`: ya lo hacen los scripts de Microsoft (Kerberos-Crypto).
- README en inglés primero, versión española después.
- Licencia: pendiente de Marcos.

# AuthScope

Módulo PowerShell de solo lectura que audita el uso de NTLM (centro del producto) y los fallos de Kerberos RC4 (diagnóstico) en todos los DC de un dominio AD, con informe HTML de un solo archivo. Ángulo de venta: seguridad (relay, pass-the-hash) + preparación para la desactivación de NTLM por defecto (sin fecha oficial).

Familia Scope de marcosblg, primera en PowerShell.

## Mapa
- `AuthScope/AuthScope.psd1` — manifiesto (exporta solo `Invoke-AuthScope`).
- `AuthScope/AuthScope.psm1` — todo el módulo:
  - `$DcCollector`: scriptblock que corre en cada DC por WinRM (registro + eventos 8004/8006, 4022/4023, 4030-4033, 4776, 4624 NTLM V1, KDC 201-209). Con `$Member` (parámetro `-MemberServer`) solo lee 8001-8003 y 4022/4023 en servidores miembros (si hay 4022/4023 se ignoran 8002/8003); esos datos llevan `Role = 'Member'`.
  - `Get-ASDcData` (recogida), `Get-ASNtlmUsage` (agrega uso NTLM), `Get-ASFinding` (reglas → hallazgos con corrección), `ConvertTo-ASHtml` (informe), `Invoke-AuthScope` (orquesta y escribe HTML/JSON/CSV).
- `tests/AuthScope.Tests.ps1` — Pester 5, con datos falsos (no necesita AD).
- `.github/workflows/ci.yml` — PSScriptAnalyzer + Pester en PS 5.1 y 7.
- `README.md` — inglés; `README.es.md` — español. `TRASPASO.md` — estado y siguiente paso.

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
- MVP solo lee DC (8004 o, si existe, registro NTLM mejorado 4022/4023/4030-4033, que sustituye a 8004/4776 en ese DC). Eventos 8001-8003 y 4022/4023 de servidores miembros: opcional con `-MemberServer` (lista explícita, sin descubrimiento automático); en miembros no se aplican las reglas de DC (auditoría 8004, DC acepta NTLMv1); solo se avisa si `LmCompatibilityLevel` explícito < 3 (el miembro envía NTLMv1).
- No se replica el inventario de `msDS-SupportedEncryptionTypes`: ya lo hacen los scripts de Microsoft (Kerberos-Crypto).
- README en inglés primero, versión española después.
- Licencia: AGPL-3.0 (como el resto de Scope).

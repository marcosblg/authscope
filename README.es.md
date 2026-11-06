# AuthScope

[English](README.md)

Auditoría en PowerShell, de solo lectura, del **uso de NTLM** y de los **fallos de Kerberos RC4** en todos los controladores de dominio de un dominio de Active Directory. Un comando, un informe HTML autocontenido con semáforo, qué está afectado y cómo corregirlo.

NTLM es la base de los ataques de relay y pass-the-hash, y Microsoft prevé desactivarlo por defecto en futuras versiones de Windows Server. AuthScope te dice quién lo sigue usando, desde qué equipo y contra qué servidor, antes de bloquearlo.

## Qué comprueba
| Comprobación | Origen |
|---|---|
| Autenticaciones NTLM por cuenta, equipo cliente y servidor destino, unidas de todos los DC | `Microsoft-Windows-NTLM/Operational` 8004 |
| Registro NTLM mejorado: NTLM hacia el DC y reenviado por el DC, con versión NTLM (sustituye a 8004/4776 en ese DC) | `Microsoft-Windows-NTLM/Operational` 4022/4023, 4030-4033 |
| NTLMv1 en uso | Campo `NtlmVersion` de los eventos mejorados |
| Validaciones de credenciales NTLM (alternativa si la auditoría 8004 está apagada) | Seguridad 4776 |
| Auditoría NTLM desactivada en un DC (el informe saldría vacío) | `AuditNTLMInDomain` |
| El DC sigue aceptando NTLMv1 / LM | `LmCompatibilityLevel` |
| Fallos de Kerberos RC4 / falta de clave AES | Sistema, eventos KDC 201-209 |

Nunca escribe en AD ni en los DC.

## Uso
```powershell
Install-Module AuthScope -Scope CurrentUser
Invoke-AuthScope -Days 14 -OutputPath C:\Informes
```
Requisitos: Windows PowerShell 5.1 o PowerShell 7, WinRM hacia cada DC y permiso para leer el registro de Seguridad (Admins. del dominio o equivalente). Sin `-ComputerName` audita todos los DC del dominio actual.

Salida: `AuthScope-<fecha>.html`, `.json` (todos los datos) y `-findings.csv`.

## Activar antes la auditoría NTLM
Windows Server 2025 y los DC 2019/2022 actualizados (KB5064479) ya traen el registro NTLM mejorado. En los demás, en la GPO de Domain Controllers: *Seguridad de red: restringir NTLM: auditar la autenticación NTLM en este dominio* = **Habilitar todo**. Déjalo unos días y luego ejecuta AuthScope.

## Desarrollo
```powershell
Invoke-Pester -Path tests
Invoke-ScriptAnalyzer -Path AuthScope -Recurse
```

## Licencia
AGPL-3.0. Ver [LICENSE](LICENSE).

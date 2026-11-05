# TRASPASO — AuthScope

## 1. Cómo trabajar con Marcos aquí
- Respuestas cortas y críticas; distinguir evidencia (con fuente) de hipótesis.
- No volver a plantear el tema de desarrollar en horario laboral: Marcos ya lo ha decidido.
- Decir claramente qué se va a hacer antes de ponerse (se pierde si solo ve herramientas).

## 2. Entorno
- Windows PowerShell 5.1 local, sin pwsh ni RSAT.
- Pester 5.7.1 y PSScriptAnalyzer NO están instalados: `Install-Module` falla porque no puede escribir en `Documents\WindowsPowerShell\Modules` (la carpeta ni se crea; probable bloqueo del sandbox o de Acceso controlado a carpetas, sin confirmar). Workaround: `Save-Module Pester -RequiredVersion 5.7.1 -Path <carpeta>` y anteponer esa carpeta a `$env:PSModulePath`.
- Laboratorio previsto en Proxmox: DC 2019, DC 2025 y un servicio/NAS con RC4 forzado y clientes que usen NTLM.
- Repo git local en `authscope/` (sin remoto). Crear `marcosblg/authscope` en GitHub (licencia ya decidida: AGPL-3.0).

## 3. Estado
- Enfoque cambiado (nov 2026): RC4 ya está en aplicación completa desde julio 2026 y Microsoft publica `List-AccountKeys.ps1`/`Get-KerbEncryptionUsage.ps1` (repo Kerberos-Crypto). Centro = NTLM; RC4 = diagnóstico de fallos (KDC 201-209).
- MVP v0.1.0 escrito: `Invoke-AuthScope` → recoge por WinRM de cada DC (8004, 4776, KDC 201-209, `AuditNTLMInDomain`, `LmCompatibilityLevel`), agrega, genera hallazgos con corrección y escribe HTML/JSON/CSV.
- 8 tests Pester en verde y PSScriptAnalyzer limpio (Warning/Error), solo con datos falsos. **Nunca ejecutado contra un AD real.**
- TenantScope: no se decide ahora. PR a Maester en paralelo (lo lleva Marcos).

## 4. Siguiente paso
1. Montar el laboratorio y ejecutar contra AD real. Verificar:
   - Nombres de campos de 8004 (`UserName`, `DomainName`, `WorkstationName`, `SChannelName`) y 4776 (`TargetUserName`, `Workstation`).
   - Proveedor y significado real de los eventos KDC 201-209 (KB5073381, CVE-2026-20833); hoy solo se agrupan por Id con el mensaje.
   - Que `AuditNTLMInDomain` es el valor de registro de la GPO "Audit NTLM authentication in this domain".
2. Revisar el HTML generado con datos reales (se ha visto solo en tests).
3. Licencia decidida: AGPL-3.0. Pendiente de Marcos: comprobar que "AuthScope" está libre en GitHub/PSGallery.
4. Después: README en español, publicar en PSGallery, modo opcional 8001-8003 en servidores miembros, detección de NTLMv1 real (4624 `LmPackageName = NTLM V1`).

## 5. Trampas conocidas
- Los eventos NTLM no se registran por defecto: sin la GPO de auditoría el informe sale vacío; la herramienta lo avisa.
- 8001 se registra en el cliente, 8002/8003 en el servidor destino, 8004 en el DC. El MVP solo ve 8004.
- `LmCompatibilityLevel` ausente = 3 (el DC acepta NTLMv1).
- `-MaxEvents` (20000 por log y DC) puede recortar datos en dominios grandes.
- NTLM no tiene fecha oficial de desactivación: no venderlo con fecha.

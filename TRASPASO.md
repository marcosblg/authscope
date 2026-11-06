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
- 8 tests Pester en verde (Pester 5.7.1 vía Save-Module en scratchpad). PSScriptAnalyzer no se ha vuelto a pasar tras el cambio de hallazgos RC4.
- **Probado en DC real** (TEKU-DC, Windows Server 2025, dominio TEKU.LOCAL = PRODUCCIÓN): recoge, genera HTML/JSON/CSV y hallazgos correctos (NTLMv1 aceptado, auditoría NTLM off, 4776 agregado).
- Verificado en DC: 8004 = proveedor `Microsoft-Windows-Security-Netlogon` en NTLM/Operational, campos `SChannelName, UserName, DomainName, WorkstationName, SChannelType`. 4776 = `TargetUserName`, `Workstation`. KDC = proveedor `Microsoft-Windows-Kerberos-Key-Distribution-Center` (log System), 201-205 en este build con `AccountName, ServiceName, IpAddress, DDSET, Cipher...`; 206-209 aún no existen en este build.
- Hallazgos RC4 ya explican cada id (tabla `$script:KdcEvents`: 203/204/208/209 bloqueo = Critical, resto Warning) con pares cuenta → servicio (IP).
- TenantScope: no se decide ahora. PR a Maester en paralelo (lo lleva Marcos).

## 4. Siguiente paso
1. Sin verificar con datos reales: 8004 con la GPO puesta, `AuditNTLMInDomain` con valor, eventos KDC reales. Ambos DC de Marcos son de TEKU (producción) y no quiere tocar GPO ahí: solo comandos de lectura. Hace falta un DC de un dominio de pruebas.
2. Pasar PSScriptAnalyzer (Save-Module igual que Pester).
3. Pendiente de Marcos: comprobar que "AuthScope" está libre en GitHub/PSGallery; luego crear repo, README en español, publicar en PSGallery.
4. Después: modo opcional 8001-8003 en servidores miembros, detección de NTLMv1 real (4624 `LmPackageName = NTLM V1`).
- Marcos no es experto en NTLM/Kerberos: explicar en llano qué hace cada comando y para qué.

## 5. Trampas conocidas
- Los eventos NTLM no se registran por defecto: sin la GPO de auditoría el informe sale vacío; la herramienta lo avisa.
- 8001 se registra en el cliente, 8002/8003 en el servidor destino, 8004 en el DC. El MVP solo ve 8004.
- `LmCompatibilityLevel` ausente = 3 (el DC acepta NTLMv1).
- Ids de eventos clásicos del KDC llevan bits de nivel (2147483651…): comparar con `Id -band 0xFFFF`.
- GPO de opciones de seguridad en "No definida" deja el valor tatuado en el registro: para deshacer, poner Deshabilitar.
- `-MaxEvents` (20000 por log y DC) puede recortar datos en dominios grandes.
- NTLM no tiene fecha oficial de desactivación: no venderlo con fecha.

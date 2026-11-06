# TRASPASO — AuthScope

## 1. Cómo trabajar con Marcos aquí
- Respuestas cortas y críticas; distinguir evidencia (con fuente) de hipótesis.
- No volver a plantear el tema de desarrollar en horario laboral: Marcos ya lo ha decidido.
- Decir claramente qué se va a hacer antes de ponerse (se pierde si solo ve herramientas).

## 2. Entorno
- Windows PowerShell 5.1 local, sin pwsh ni RSAT.
- Pester 5.7.1 y PSScriptAnalyzer NO instalados (`Install-Module` no puede escribir en Documents). Workaround: `Save-Module <mod> -Path <scratchpad>\mods` y anteponer esa carpeta a `$env:PSModulePath`.
- Pruebas reales: TEKU-DC (Server 2025, TEKU.LOCAL). Marcos permite usarlo para pruebas si no se rompe nada y se deshace después. No hay servidor miembro (el otro DC 2019 anidado se va a retirar).
- Remoto: https://github.com/marcosblg/authscope (rama `master`).

## 3. Estado
- Enfoque cambiado (nov 2026): RC4 ya está en aplicación completa desde julio 2026 y Microsoft publica `List-AccountKeys.ps1`/`Get-KerbEncryptionUsage.ps1` (repo Kerberos-Crypto). Centro = NTLM; RC4 = diagnóstico de fallos (KDC 201-209).
- MVP v0.1.0 escrito: `Invoke-AuthScope` → recoge por WinRM de cada DC (8004, 4776, KDC 201-209, `AuditNTLMInDomain`, `LmCompatibilityLevel`), agrega, genera hallazgos con corrección y escribe HTML/JSON/CSV.
- 10 tests Pester en verde; PSScriptAnalyzer limpio (Warning/Error).
- v0.1.1 (en git, NO publicada en PSGallery): NTLMv1 en DC sin registro mejorado vía Seguridad 4624 `LmPackageName = NTLM V1` (filas Source 4624, Version NTLMv1, Target = el DC). Solo cuenta si el DC no tiene 4022/4023/4030-4033 (si no, doble conteo). Filtro XPath verificado en local; sin probar contra un DC real (el clasificador de permisos bloqueó Invoke-Command a TEKU-DC).
- Registro NTLM mejorado (KB5064479, por defecto en 2025/24H2 y en 2019/2022 desde oct 2026): se recogen 4022/4023 (NTLM hacia el DC) y 4030-4033 (reenviado por el DC). Si un DC tiene estos eventos, se ignoran sus 8004/4776 (evita doble conteo). Columna `Version` (NtlmVersion) y hallazgo Critical "NTLMv1 in use". Sin estos eventos ni GPO, sigue el aviso "auditing is off".
- 4022 verificado con evento real (NtlmVersion='NTLMv2'); 4030-4033 solo por plantilla (no hay servidor miembro).
- **Probado en DC real** (TEKU-DC, Windows Server 2025, dominio TEKU.LOCAL): recoge, genera HTML/JSON/CSV y hallazgos correctos (NTLMv1 aceptado, auditoría NTLM off, 4776 agregado).
- Verificado en DC: 8004 = proveedor `Microsoft-Windows-Security-Netlogon` en NTLM/Operational, campos `SChannelName, UserName, DomainName, WorkstationName, SChannelType`. 4776 = `TargetUserName`, `Workstation`. KDC = proveedor `Microsoft-Windows-Kerberos-Key-Distribution-Center` (log System), 201-205 en este build con `AccountName, ServiceName, IpAddress, DDSET, Cipher...`; 206-209 aún no existen en este build.
- Hallazgos RC4 ya explican cada id (tabla `$script:KdcEvents`: 203/204/208/209 bloqueo = Critical, resto Warning) con pares cuenta → servicio (IP).
- TenantScope: no se decide ahora. PR a Maester en paralelo (lo lleva Marcos).

## 4. Siguiente paso
1. TEKU-DC limpio (GPO de auditoría NTLM en Deshabilitar, carpeta authscope borrada, nov 2026). `AuditNTLMInDomain`=7 verificado.
2. Sin verificar con datos reales: 8004 y 4030-4033 (necesitan un servidor miembro), eventos KDC reales.
3. Publicado (6 nov 2026): GitHub https://github.com/marcosblg/authscope (CI verde PS 5.1/7) y PSGallery https://www.powershellgallery.com/packages/AuthScope v0.1.0 (verificado con Save-PSResource). Siguiente: probar `Install-Module AuthScope` en máquina limpia y post en LinkedIn unos días después (gancho: quién usa NTLM antes de que Microsoft lo apague, sin fecha; captura del informe anonimizada). Pendiente de Marcos: borrar las API keys `authscope` y `authscope-publicar` (la segunda quedó expuesta en el chat).
4. Publicar 0.1.1 en PSGallery (clave de Marcos, ver trampas) y probar 4624 en un DC real (en TEKU-DC habrá 0 eventos V1 salvo que se fuerce un cliente NTLMv1).
5. Después: modo opcional 8001-8003 en servidores miembros.
- Marcos no es experto en NTLM/Kerberos: explicar en llano qué hace cada comando y para qué.

## 5. Trampas conocidas
- Los eventos NTLM no se registran por defecto: sin la GPO de auditoría el informe sale vacío; la herramienta lo avisa.
- 8001 se registra en el cliente, 8002/8003 en el servidor destino, 8004 en el DC. El MVP solo ve 8004.
- 8004 solo sale cuando el DC valida NTLM para un servidor miembro; NTLM contra el propio DC no genera 8004.
- En 4022 real, `TargetMachine`/`TargetDomain` vienen intercambiados; no se usan.
- En `switch`, la condición `{ $_ -ge 4030 }` también casa con 8004: usar rangos exactos.
- `LmCompatibilityLevel` ausente = 3 (el DC acepta NTLMv1).
- Ids de eventos clásicos del KDC llevan bits de nivel (2147483651…): comparar con `Id -band 0xFFFF`.
- GPO de opciones de seguridad en "No definida" deja el valor tatuado en el registro: para deshacer, poner Deshabilitar.
- `Get-WinEvent -FilterHashtable` con claves de EventData (p. ej. `LmPackageName`) devuelve 0 en PS 5.1 sin error: usar `-FilterXPath` (Get-Ev acepta `@{ LogName; XPath }`).
- 4624 V1 en el DC solo ve inicios de sesión contra el propio DC, no el NTLM reenviado a servidores miembros (eso lo da 8004 sin versión).
- `-MaxEvents` (20000 por log y DC) puede recortar datos en dominios grandes.
- NTLM no tiene fecha oficial de desactivación: no venderlo con fecha.
- Publicar: PowerShellGet local es 1.0.0.1 (no fiable). Usar PSResourceGet: `Save-Module Microsoft.PowerShell.PSResourceGet -Path <dir>`, importarlo y `Publish-PSResource -Path .\AuthScope -Repository PSGallery -ApiKey <clave>`; subir `ModuleVersion` antes. La clave la pega Marcos (Read-Host). Ojo: el login puede acabar en `psgallery.azure.com`, que NO es la galería oficial; usar www.powershellgallery.com.
- Push con `.github/workflows/` exige token con scope `workflow` (`gh auth refresh -s workflow`).

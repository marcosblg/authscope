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
- v0.1.1 (publicada en PSGallery, 6 nov 2026): NTLMv1 en DC sin registro mejorado vía Seguridad 4624 `LmPackageName = NTLM V1` (filas Source 4624, Version NTLMv1, Target = el DC). Solo cuenta si el DC no tiene 4022/4023/4030-4033 (si no, doble conteo). Filtro XPath verificado en local; sin probar contra un DC real (el clasificador de permisos bloqueó Invoke-Command a TEKU-DC).
- Registro NTLM mejorado (KB5064479, por defecto en 2025/24H2 y en 2019/2022 desde oct 2026): se recogen 4022/4023 (NTLM hacia el DC) y 4030-4033 (reenviado por el DC). Si un DC tiene estos eventos, se ignoran sus 8004/4776 (evita doble conteo). Columna `Version` (NtlmVersion) y hallazgo Critical "NTLMv1 in use". Sin estos eventos ni GPO, sigue el aviso "auditing is off".
- 4022 verificado con evento real (NtlmVersion='NTLMv2'); 4030-4033 solo por plantilla (no hay servidor miembro).
- **Probado en DC real** (TEKU-DC, Windows Server 2025, dominio TEKU.LOCAL): recoge, genera HTML/JSON/CSV y hallazgos correctos (NTLMv1 aceptado, auditoría NTLM off, 4776 agregado).
- Verificado en DC: 8004 = proveedor `Microsoft-Windows-Security-Netlogon` en NTLM/Operational, campos `SChannelName, UserName, DomainName, WorkstationName, SChannelType`. 4776 = `TargetUserName`, `Workstation`. KDC = proveedor `Microsoft-Windows-Kerberos-Key-Distribution-Center` (log System), 201-205 en este build con `AccountName, ServiceName, IpAddress, DDSET, Cipher...`; 206-209 aún no existen en este build.
- Hallazgos RC4 ya explican cada id (tabla `$script:KdcEvents`: 203/204/208/209 bloqueo = Critical, resto Warning) con pares cuenta → servicio (IP).
- v0.2.0 (publicada en PSGallery y GitHub, 6 nov 2026; en la galería hay 0.1.0, 0.1.1 y 0.2.0): `-MemberServer FS1, SQL1` lee 8001-8003 en servidores miembros (mismo `$DcCollector` con `$Member`, filas `Role = 'Member'`). Campos sacados del manifiesto del proveedor `Microsoft-Windows-NTLM` (Get-WinEvent -ListProvider): 8001 `TargetName, UserName, DomainName, ProcessName`; 8002 solo `ProcessName` del proceso local (sin usuario/cliente remoto); 8003 `UserName, DomainName, Workstation, ProcessName`. En miembros no se aplican reglas de DC; sin eventos → aviso con las GPO de auditoría. 11 tests en verde, PSSA limpio. Recolector probado en local (0 eventos, sin errores); sin probar contra un miembro real.
- v0.2.1 (publicada en PSGallery y GitHub, 6 nov 2026; última; en la galería: 0.1.0, 0.1.1, 0.2.0, 0.2.1): prueba real en TEKU-DC (6 nov 2026) con auditoría NTLM entrante y `net use` por IP desde APLUSSERVER (10.10.33.51). Evidencia: 4022 sale en cualquier servidor que recibe NTLM, sin GPO, con `Username` en UPN y `DomainName`='Null'; 8002 trae `ClientUserName`=cuenta del propio servidor (TEKU-DC$), sin usuario remoto; 8003 no salió; 4030 real coincide con los campos del código; 8006 = como 8004 para reenvío a dominio que confía (trust APLUS.LOCAL). Cambios: modo miembro lee 4022/4023 y con ellos ignora 8002/8003; 8006 se cuenta como 8004; usuario de 4022 sin 'Null\'. 12 tests, PSSA limpio. `Invoke-AuthScope -MemberServer` de punta a punta aún sin ejecutar.
- TenantScope: no se decide ahora. PR a Maester en paralelo (lo lleva Marcos).

## 4. Siguiente paso
1. TEKU-DC limpio (GPO de auditoría NTLM en Deshabilitar, carpeta authscope borrada, nov 2026). `AuditNTLMInDomain`=7 verificado.
2. Sin verificar con datos reales: 8004 y 4030-4033 (necesitan un servidor miembro), eventos KDC reales.
3. Publicado (6 nov 2026): GitHub https://github.com/marcosblg/authscope (CI verde PS 5.1/7) y PSGallery https://www.powershellgallery.com/packages/AuthScope (última 0.2.1, verificada por la API v2 de la galería). Instalación desde la galería probada (6 nov 2026) en proceso limpio (`-NoProfile`, PSModulePath aislado): 0.2.1 se descarga, sus psd1/psm1 son idénticos al repo (hash), importa, exporta solo `Invoke-AuthScope` y con un DC inexistente acaba limpio (hallazgo "DC not reachable" + HTML/JSON/CSV). `Install-Module` local falla solo al copiar en Documents (trampa del entorno); falta una VM de verdad, sin perfil, si Marcos quiere. Post de LinkedIn listo (ES + EN) en `linkedin/post.md` con captura `linkedin/authscope-demo.png` (datos ficticios CONTOSO); `linkedin/` excluido de git vía `.git/info/exclude`. Afirmaciones del post verificadas con Microsoft (FAQ "Retiring NTLM", KB5064479, KB5066470) y corregidas; Marcos lo publica el martes 10 nov 2026.
   - "DC accepts NTLMv1" en DC 2025: correcto, sin 0.2.2. Probado en TEKU-DC (10 nov 2026): APLUSSERVER (2019) con `LmCompatibilityLevel`=1 temporal (revertido, antes no existía), `net use \\10.10.33.52\IPC$` → 4023 `NTLMv1` `STATUS_SUCCESS` y 4624 `LmPackageName`=`NTLM V1`. El DC 2025 sin `LmCompatibilityLevel` acepta NTLMv1 (KB5066470 solo cubre el lado cliente). Las API keys se crean con caducidad de 1 día y Glob `AuthScope`; Marcos la pega en una pestaña de terminal (script con Read-Host -AsSecureString), nunca en el chat.
4. 4624 V1 y 4023 NTLMv1 verificados con eventos reales en TEKU-DC (10 nov 2026). `Invoke-AuthScope` 0.2.1 de la galería (Save-Module a C:\Temp, sin instalar) contra TEKU-DC: Critical "NTLMv1 in use: 1" (4023, TEKU\Administrador desde APLUSSERVER, sin doble conteo con 4624) + Warning LmCompatibilityLevel. Siguiente: Marcos postea (no hace falta versión nueva).
5. TEKU-DC revertido por Marcos tras la prueba de 0.2.1 (auditoría NTLM entrante en Deshabilitar).
6. v0.2.2 (commit e4952b6, push a master, 10 nov 2026): en miembros, Warning "Server sends NTLMv1" si `LmCompatibilityLevel` es explícito y < 3 (ausente = 3, no avisa). README EN/ES: nota de que `-MemberServer` no se ha probado contra un miembro real. 13 tests, PSSA limpio. Publicación en PSGallery: la lanza Marcos con `<scratchpad>\publicar.ps1` (PSResourceGet + Read-Host); pendiente confirmar en la galería.
- Marcos no es experto en NTLM/Kerberos: explicar en llano qué hace cada comando y para qué.

## 5. Trampas conocidas
- Los eventos NTLM no se registran por defecto: sin la GPO de auditoría el informe sale vacío; la herramienta lo avisa.
- 8001 se registra en el cliente, 8002/8003 en el servidor destino, 8004 en el DC. Un mismo inicio de sesión puede contarse en 8004 (DC) y 8003 (miembro): totales por servidor duplicados (shortcut documentado).
- `$DcCollector` invocado en local hereda StrictMode del módulo (en remoto no): no acceder a claves ausentes de hashtables (`ContainsKey`).
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
- `Save-Module -Path` falla si la carpeta no existe: crearla antes (`New-Item -ItemType Directory`).
- Push con `.github/workflows/` exige token con scope `workflow` (`gh auth refresh -s workflow`).

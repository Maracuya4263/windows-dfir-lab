# Adquisición de evidencia en vivo en Windows — Kit de scripts DFIR

> Conjunto de scripts de PowerShell para **adquisición forense en vivo** de un sistema Windows
> comprometido, en un laboratorio aislado. Desarrollados como parte de trabajo de ciberseguridad
> (últimos semestres, Universidad Nacional de Colombia). Uso estrictamente **defensivo / DFIR**.

## Principios de diseño

Los cinco scripts comparten los mismos principios de forense digital:

- **Orden de volatilidad (RFC 3227).** Se ejecutan de lo **más volátil** (RAM) a lo **menos volátil**
  (disco), para no perder evidencia efímera: `RAM → red/procesos → captura de tráfico → registro → disco`.
- **Mínimo impacto en la víctima (fileless donde es posible).** La evidencia se transmite **en vivo**
  por un túnel a la estación del analista (Kali), sin escribir —o escribiendo lo mínimo— en el sistema
  comprometido. Esto reduce la contaminación de la evidencia y la huella del proceso de adquisición.
- **Cifrado en tránsito (TLS 1.2).** Todo viaja por un socket TLS 1.2 estricto hacia un receptor
  `ncat --ssl` en Kali.
- **Integridad (SHA-256 en vuelo).** El hash se calcula **durante** el streaming en el origen; luego
  se compara con el hash del archivo recibido en Kali (`sha256sum`). Garantiza que lo que llegó es
  exactamente lo que salió.
- **Cadena de custodia.** Timestamps por sección, hostname/usuario, y (en el registro) un *manifest*
  que viaja junto a la evidencia para verificar cada artefacto por separado.

## Preparación del receptor (Kali)

Cada script transmite a un puerto distinto para poder correr en secuencia. En Kali, **antes** de lanzar
cada script, se abre el receptor TLS correspondiente:

```bash
# Generar el par de certificados una sola vez
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=kali"

# Un receptor por script (puerto según la tabla de abajo). Ejemplo (RAM, puerto 4444):
ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -l 4444 > ram.mem
```

## Resumen de los scripts

| Orden | Script | Qué captura | Puerto Kali | Impacto en disco de la víctima |
|---|---|---|---|---|
| 0 | `Script0_RAM.ps1` | Memoria RAM completa (winpmem) | 4444 | Ninguno (diskless / read-only) |
| 1 | `ScriptA_Red_Config.ps1` | Procesos, conexiones TCP, rutas, interfaces, ARP | 4443 | Ninguno (todo en RAM → TLS) |
| 2 | `ScriptB_Pktmon_Red.ps1` | Captura de tráfico de red (pktmon → pcapng) | 4444 | Mínimo (un flush al detener) |
| 3 | `ScriptC_Registro.ps1` | Hives del registro (SAM, SYSTEM, SOFTWARE) | 4445 | Temporal (se limpia siempre) |
| 4 | `ScriptD_Disco.ps1` | Imagen cruda del disco (dd.exe) | 4446 | Ninguno (diskless) |

> Los scripts 0 y B usan ambos el 4444 porque están pensados para ejecutarse en momentos distintos; si
> se corren en paralelo, cambiar uno de los puertos con el parámetro `-KALI_PORT`.

---

## Script 0 — Adquisición de memoria RAM (winpmem)

**Orden de ejecución:** 0 · el más volátil  |  **Archivo:** `scripts/Script0_RAM.ps1`

Vuelca la **memoria física completa** con `winpmem.exe`, enviándola **directo por la red** a Kali
sin tocar el disco de la víctima (*diskless / read-only*). winpmem escribe a `STDOUT` (`-`) y ese flujo
se cifra con TLS 1.2 y se transmite mientras, en paralelo, se calcula el SHA-256 en vuelo. Es el primer
artefacto que se debe capturar: procesos, conexiones, claves en memoria y payloads *fileless* solo viven
aquí. Al final imprime el hash de origen y los comandos exactos para renombrar y verificar en Kali.

**Requisitos:** `winpmem.exe` en el directorio, PowerShell como Administrador.
**Receptor Kali:** `ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -l 4444 > ram.mem`

```powershell
param(
    [string]$KALI_IP     = "20.0.0.2",
    [int]$KALI_PORT      = 4444,
    [string]$WinPmemPath = ".\winpmem.exe"
)

$ErrorActionPreference = "Stop"

# ============================================================
# DFIR RAM Acquisition - DISKLESS, READ-ONLY & ENCRYPTED (TLS)
# ============================================================

if (-not (Test-Path $WinPmemPath)) {
    Write-Error "No encontrado: $WinPmemPath"
    exit 1
}

$timestamp = Get-Date -Format "ddMMyyyy-HHmm"
$finalFileName = "windows10-$timestamp.mem"

Write-Host ""
Write-Host "========================================================="
Write-Host " ADQUISICION FORENSE DE RAM (MODO OPSEC STRICT v2)"
Write-Host "========================================================="
Write-Host "[*] Destino:       $KALI_IP : $KALI_PORT"
Write-Host "[*] Archivo final: $finalFileName"
Write-Host "[*] Encriptacion:  TLS 1.2 (Estricto)"
Write-Host "========================================================="
Write-Host ""

# ============================================================
# Conectar a Kali por Socket TLS
# ============================================================
Write-Host "[*] Estableciendo tunel TLS con $KALI_IP..."

try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient($KALI_IP, $KALI_PORT)
    # Aumentar el tiempo de espera (Timeout) para redes lentas
    $tcpClient.SendTimeout = 60000 
    $netStream = $tcpClient.GetStream()

    $certCallback = [System.Net.Security.RemoteCertificateValidationCallback] { return $true }
    $sslStream = New-Object System.Net.Security.SslStream($netStream, $false, $certCallback)
    
    # FORZAR TLS 1.2
    $sslProtocol = [System.Security.Authentication.SslProtocols]::Tls12
    $sslStream.AuthenticateAsClient($KALI_IP, $null, $sslProtocol, $false)
}
catch {
    Write-Error "No se pudo establecer el túnel TLS. ¿Verificaste usar 'ncat --ssl' en Kali?"
    exit 1
}

Write-Host "[+] Tunel encriptado establecido (TLS 1.2)."

# ============================================================
# Configurar WinPMEM para STDOUT
# ============================================================
$winpmemInfo = New-Object System.Diagnostics.ProcessStartInfo
$winpmemInfo.FileName = $WinPmemPath
$winpmemInfo.Arguments = "-" 
$winpmemInfo.UseShellExecute = $false
$winpmemInfo.RedirectStandardOutput = $true
$winpmemInfo.RedirectStandardError = $true
$winpmemInfo.CreateNoWindow = $true

$winpmemProcess = New-Object System.Diagnostics.Process
$winpmemProcess.StartInfo = $winpmemInfo

$winpmemStarted = $winpmemProcess.Start()
if (-not $winpmemStarted) {
    Write-Error "No se pudo iniciar WinPMEM"
    exit 1
}

$sourceStream = $winpmemProcess.StandardOutput.BaseStream

# ============================================================
# Transferencia + HASH
# ============================================================
Write-Host "[*] Iniciando volcado de RAM directo por la red..."
Write-Host ""

$sha256Provider = [System.Security.Cryptography.SHA256]::Create()
# Reducimos el Buffer a 64KB para evitar sobrecargar el túnel TLS
$buffer = New-Object byte[] (64 * 1024) 
$totalBytes = 0

try {
    while (($readCount = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $sha256Provider.TransformBlock($buffer, 0, $readCount, $null, 0) | Out-Null
        
        $sslStream.Write($buffer, 0, $readCount)
        $sslStream.Flush()
        
        $totalBytes += $readCount
        $currentMB = [math]::Round($totalBytes / 1MB, 1)
        Write-Host -NoNewline "`r[*] Transferidos y encriptados: $currentMB MiB"
    }
}
catch {
    Write-Host "`n[!] ERROR durante la transferencia de red: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    Write-Host ""
    try { if ($sourceStream) { $sourceStream.Close() } } catch {}
    try { if ($sslStream) { $sslStream.Close() } } catch {}
    try { if ($netStream) { $netStream.Close() } } catch {}
    try { if ($tcpClient) { $tcpClient.Close() } } catch {}
}

# ============================================================
# Finalizar HASH
# ============================================================
$sha256Provider.TransformFinalBlock(@(), 0, 0) | Out-Null
$finalHash = ([BitConverter]::ToString($sha256Provider.Hash)).Replace("-", "")

if ($winpmemProcess -ne $null) {
    $winpmemProcess.WaitForExit(5000) | Out-Null
}

# ============================================================
# Resultado final
# ============================================================
Write-Host ""
Write-Host "===========================================================" -ForegroundColor Green
Write-Host "                ADQUISICION COMPLETADA" -ForegroundColor Green
Write-Host "===========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "SHA256 (Origen):"
Write-Host "  $finalHash" -ForegroundColor Yellow
Write-Host ""
Write-Host "Transferido:"
Write-Host "  $([math]::Round($totalBytes / 1MB, 1)) MiB"
Write-Host ""
Write-Host "==========================================================="
Write-Host "Pasos finales en tu terminal de Kali:"
Write-Host "1. Presiona Ctrl+C si ncat no se ha cerrado solo."
Write-Host ""
Write-Host "2. Copia y pega esto para renombrar el archivo:" -ForegroundColor Cyan
Write-Host "   mv /home/kali/evidencia/ram-temporal.mem /home/kali/evidencia/$finalFileName" -ForegroundColor White
Write-Host ""
Write-Host "3. Copia y pega esto para verificar el HASH:" -ForegroundColor Cyan
Write-Host "   echo `"$finalHash  /home/kali/evidencia/$finalFileName`" | sha256sum -c" -ForegroundColor White
Write-Host "==========================================================="
Write-Host ""
```

---

## Script A — Configuración de red, conexiones y procesos

**Orden de ejecución:** 1  |  **Archivo:** `scripts/ScriptA_Red_Config.ps1`

Captura los artefactos **volátiles de red y procesos**: procesos en ejecución (`Get-Process`),
conexiones TCP activas (`Get-NetTCPConnection`), tabla de enrutamiento, `ipconfig /all`, tabla ARP y
adaptadores. Todo se arma en un buffer **en RAM** y se transmite por TLS — **cero escritura en disco**.
Cada sección lleva su propio timestamp (los procesos y conexiones cambian en segundos), y todo se sella
con SHA-256 en vuelo.

**Receptor Kali:** `ncat --ssl ... -l 4443 > red_config.txt`

```powershell
# =====================================================================
#  SCRIPT A  |  Configuración de Red, Conexiones y Procesos Activos
#  Orden de ejecución : 1° (datos más volátiles)
#  Puerto Kali        : 4443
#  Impacto en disco   : CERO — todo en RAM hasta el envío TLS
# =====================================================================
#  Kali (ejecutar ANTES):
#    ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -l 4443 > red_config.txt
# =====================================================================

param(
    [string]$KALI_IP  = "20.0.0.2",
    [int]$KALI_PORT   = 4443
)
$ErrorActionPreference = "Stop"

Write-Host "========================================================="
Write-Host " ADQUISICION FORENSE - CONFIG DE RED (SCRIPT A - 1ro)"
Write-Host "========================================================="
Write-Host "[*] Destino : $KALI_IP : $KALI_PORT"
Write-Host "[*] Modo    : FILELESS (sin escritura en disco)"

$sb = New-Object System.Text.StringBuilder

$sb.AppendLine("==========================================================")
$sb.AppendLine(" EVIDENCIA FORENSE - CONFIGURACION DE RED")
$sb.AppendLine(" Script iniciado: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')")
$sb.AppendLine("==========================================================")

# ── SECCIÓN 1: Procesos activos ───────────────────────────────────────
# [FIX] Agregado: Get-Process es un artefacto volátil crítico. Debe
# capturarse primero porque los procesos pueden terminar en segundos.
Write-Host "[*] Capturando procesos activos (Get-Process)..."
$sb.AppendLine("`n=== PROCESOS EN EJECUCION (Get-Process) ===")
$sb.AppendLine("Timestamp: $(Get-Date -Format 'HH:mm:ss.fff')")
try   { $sb.AppendLine((Get-Process | Sort-Object CPU -Descending | Format-List Id, ProcessName, CPU, WorkingSet, Path | Out-String).Trim()) }
catch { $sb.AppendLine("ERROR: $_") }

# ── SECCIÓN 2: Conexiones TCP activas ─────────────────────────────────
# [FIX] Timestamp individual: las conexiones cambian cada segundo.
Write-Host "[*] Capturando conexiones TCP (Get-NetTCPConnection)..."
$sb.AppendLine("`n=== CONEXIONES TCP ACTIVAS (Get-NetTCPConnection) ===")
$sb.AppendLine("Timestamp: $(Get-Date -Format 'HH:mm:ss.fff')")
try   { $sb.AppendLine((Get-NetTCPConnection | Sort-Object State | Format-List | Out-String).Trim()) }
catch { $sb.AppendLine("ERROR: $_") }

# ── SECCIÓN 3: Tabla de enrutamiento ─────────────────────────────────
# [FIX] Format-List reemplaza Format-Table -AutoSize para evitar
# truncamiento silencioso de columnas según ancho de consola.
Write-Host "[*] Capturando tabla de enrutamiento (Get-NetRoute)..."
$sb.AppendLine("`n=== TABLA DE ENRUTAMIENTO (Get-NetRoute) ===")
$sb.AppendLine("Timestamp: $(Get-Date -Format 'HH:mm:ss.fff')")
try   { $sb.AppendLine((Get-NetRoute | Sort-Object RouteMetric | Format-List | Out-String).Trim()) }
catch { $sb.AppendLine("ERROR: $_") }

# ── SECCIÓN 4: Interfaces (ipconfig /all) ─────────────────────────────
Write-Host "[*] Capturando config de interfaces (ipconfig /all)..."
$sb.AppendLine("`n=== CONFIGURACION DE INTERFACES (ipconfig /all) ===")
$sb.AppendLine("Timestamp: $(Get-Date -Format 'HH:mm:ss.fff')")
try   { $sb.AppendLine((& cmd.exe /c "ipconfig /all" 2>&1) -join "`n") }
catch { $sb.AppendLine("ERROR: $_") }

# ── SECCIÓN 5: Tabla ARP ──────────────────────────────────────────────
Write-Host "[*] Capturando tabla ARP (Get-NetNeighbor)..."
$sb.AppendLine("`n=== TABLA ARP (Get-NetNeighbor) ===")
$sb.AppendLine("Timestamp: $(Get-Date -Format 'HH:mm:ss.fff')")
try   { $sb.AppendLine((Get-NetNeighbor | Format-List | Out-String).Trim()) }
catch { $sb.AppendLine("ERROR: $_") }

# ── SECCIÓN 6: Adaptadores ────────────────────────────────────────────
Write-Host "[*] Capturando adaptadores (Get-NetAdapter)..."
$sb.AppendLine("`n=== ADAPTADORES DE RED (Get-NetAdapter) ===")
$sb.AppendLine("Timestamp: $(Get-Date -Format 'HH:mm:ss.fff')")
try   { $sb.AppendLine((Get-NetAdapter | Format-List | Out-String).Trim()) }
catch { $sb.AppendLine("ERROR: $_") }

$sb.AppendLine("`n==========================================================")
$sb.AppendLine(" Recolección finalizada: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')")
$sb.AppendLine("==========================================================")

$textBytes    = [System.Text.Encoding]::UTF8.GetBytes($sb.ToString())
$sourceStream = New-Object System.IO.MemoryStream($textBytes, 0, $textBytes.Length)
Write-Host "[+] Datos recolectados: $([math]::Round($textBytes.Length / 1KB, 1)) KiB (en RAM)"

# ── Conexión TLS ──────────────────────────────────────────────────────
Write-Host "[*] Estableciendo tunel TLS 1.2..."
try {
    $tcpClient  = New-Object System.Net.Sockets.TcpClient($KALI_IP, $KALI_PORT)
    $tcpClient.SendTimeout = 30000
    $netStream  = $tcpClient.GetStream()
    $certCB     = [System.Net.Security.RemoteCertificateValidationCallback] { return $true }
    $sslStream  = New-Object System.Net.Security.SslStream($netStream, $false, $certCB)
    $sslStream.AuthenticateAsClient($KALI_IP, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
    Write-Host "[+] TLS 1.2 establecido"
} catch { Write-Error "[-] Error TLS: $_"; exit 1 }

# ── Streaming con hash en vuelo ───────────────────────────────────────
$sha256     = [System.Security.Cryptography.SHA256]::Create()
$buffer     = New-Object byte[] (8 * 1024)
$totalBytes = 0

try {
    while (($n = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $sha256.TransformBlock($buffer, 0, $n, $null, 0) | Out-Null
        $sslStream.Write($buffer, 0, $n)
        $sslStream.Flush()
        $totalBytes += $n
        Write-Host -NoNewline "`r[*] Transferidos: $totalBytes bytes"
    }
} finally {
    $sourceStream.Close(); $sslStream.Close(); $tcpClient.Close()
}

$sha256.TransformFinalBlock(@(), 0, 0) | Out-Null
$finalHash = ([BitConverter]::ToString($sha256.Hash)).Replace("-", "")
Write-Host "`n[+] Transferencia completa : $totalBytes bytes"
Write-Host "[+] SHA256 Origen          : $finalHash"
Write-Host "[!] Verificar en Kali      : sha256sum red_config.txt"
```

---

## Script B — Captura de tráfico de red (pktmon)

**Orden de ejecución:** 2  |  **Archivo:** `scripts/ScriptB_Pktmon_Red.ps1`

Graba el **tráfico de red** con `pktmon` nativo en **modo memory** (buffer en RAM, un solo flush a
disco al detener), convierte el `.etl` a `.pcapng` (analizable en Wireshark) y lo transmite por TLS con
hash en vuelo. Incluye detalles de rigor forense: inventario de componentes de pktmon (reproducibilidad),
verificación real del estado con `pktmon status` (no solo el *exit code*), manejo de la *race condition*
del flush a disco (espera a que el ETL se estabilice) y limpieza de temporales al final.

**Requisitos:** Windows 10 1809+ (pktmon) / 2004+ (etl2pcap), Administrador.
**Receptor Kali:** `ncat --ssl ... -l 4444 > captura.pcapng`

```powershell
# =====================================================================
#  SCRIPT B  |  Captura de Tráfico de Red (pktmon)
#  Orden de ejecución : 2°
#  Puerto Kali        : 4444
#  Herramienta        : pktmon.exe nativo (Windows 10 1809+)
#                       etl2pcap requiere Windows 10 2004+
#  Impacto en disco   : MÍNIMO — un solo flush al detener (modo memory)
# =====================================================================
#  Kali (ejecutar ANTES):
#    ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -l 4444 > captura.pcapng
# =====================================================================

param(
    [string]$KALI_IP      = "20.0.0.2",
    [int]$KALI_PORT       = 4444,
    [int]$CapturaSecs     = 60,
    [int]$BufferMB        = 128,     # [FIX] 128 MB por defecto — 64 MB es insuficiente
    [string]$TempDir      = $env:TEMP
)
$ErrorActionPreference = "Stop"

$ts         = Get-Date -Format "ddMMyyyy_HHmm"
$etlFile    = Join-Path $TempDir "lab_${ts}.etl"
$pcapngFile = Join-Path $TempDir "lab_${ts}.pcapng"

Write-Host "========================================================="
Write-Host " ADQUISICION FORENSE - CAPTURA DE RED (SCRIPT B - 2do)"
Write-Host "========================================================="
Write-Host "[*] Destino   : $KALI_IP : $KALI_PORT"
Write-Host "[*] Duracion  : $CapturaSecs segundos"
Write-Host "[*] Log mode  : memory (buffer $BufferMB MB en RAM)"

# [FIX] Advertir si el buffer es pequeño para la duración elegida
if ($BufferMB -lt 64) {
    Write-Host "[!] ADVERTENCIA: buffer menor a 64 MB puede desbordar en redes activas."
    Write-Host "[!] Paquetes más viejos se pierden sin advertencia cuando el buffer se llena."
}

# ── Inventario de componentes (para reproducibilidad del informe) ─────
# [FIX] Registrar qué componentes monitoreaba pktmon en el momento
# de la captura. Sin esto, no se puede reproducir el experimento.
Write-Host "[*] Registrando inventario de componentes pktmon..."
$compList = & pktmon comp list 2>&1
Write-Host "[+] Componentes disponibles:"
$compList | ForEach-Object { Write-Host "    $_" }

# ── Limpiar estado previo ─────────────────────────────────────────────
Write-Host "[*] Reseteando estado previo de pktmon..."
& pktmon stop 2>&1 | Out-Null
& pktmon filter remove 2>&1 | Out-Null

# ── Iniciar captura en modo MEMORY ───────────────────────────────────
# -m memory: buffer en RAM, disco solo al ejecutar pktmon stop
Write-Host "[*] Iniciando captura (modo memory)..."
$startOutput = & pktmon start -c --pkt-size 0 -m memory -s $BufferMB -f $etlFile 2>&1

# [FIX] Verificar inicio real con pktmon status, no solo exit code.
# pktmon puede retornar 0 pero no estar capturando.
$statusOutput = & pktmon status 2>&1
$isRunning = ($statusOutput | Out-String) -match "(?i)(active|running|capturing)"
if (-not $isRunning) {
    Write-Host "[!] Salida de pktmon start: $startOutput"
    Write-Host "[!] Salida de pktmon status: $statusOutput"
    Write-Error "[-] pktmon no está en estado activo. Verificar: (1) Admin, (2) Windows 10 1809+"
    exit 1
}
Write-Host "[+] Captura activa — buffer en RAM, disco limpio"

# ── Temporizador ──────────────────────────────────────────────────────
for ($i = $CapturaSecs; $i -gt 0; $i--) {
    Write-Host -NoNewline "`r[*] Capturando... tiempo restante: $i s  "
    Start-Sleep 1
}
Write-Host ""

# ── Detener captura ───────────────────────────────────────────────────
Write-Host "[*] Deteniendo captura (flush RAM → disco)..."
& pktmon stop 2>&1 | Out-Null

# [FIX] Race condition corregida: esperar hasta que el ETL exista
# y tenga tamaño estable, en lugar de un Start-Sleep fijo.
$maxWaitSecs = 15
$waited = 0
$prevSize = -1
Write-Host "[*] Esperando que ETL se estabilice en disco..."
while ($waited -lt $maxWaitSecs) {
    Start-Sleep 1
    $waited++
    if (Test-Path $etlFile) {
        $curSize = (Get-Item $etlFile).Length
        if ($curSize -gt 0 -and $curSize -eq $prevSize) { break }
        $prevSize = $curSize
        Write-Host -NoNewline "`r[*] ETL creciendo: $([math]::Round($curSize / 1MB, 2)) MiB (${waited}s)  "
    }
}
Write-Host ""

if (-not (Test-Path $etlFile) -or (Get-Item $etlFile).Length -eq 0) {
    Write-Error "[-] ETL vacío o no encontrado en $etlFile. pktmon no capturó tráfico."
    exit 1
}
$etlSize = [math]::Round((Get-Item $etlFile).Length / 1MB, 2)
Write-Host "[+] ETL listo: $etlSize MiB"

# ── Convertir ETL → pcapng ────────────────────────────────────────────
Write-Host "[*] Convirtiendo ETL a pcapng (requiere Windows 10 2004+)..."
& pktmon etl2pcap $etlFile --out $pcapngFile 2>&1 | Out-Null

if (-not (Test-Path $pcapngFile) -or (Get-Item $pcapngFile).Length -eq 0) {
    Write-Error "[-] etl2pcap falló. Requiere Windows 10 2004+. ETL disponible en: $etlFile"
    exit 1
}
$pcapSize = [math]::Round((Get-Item $pcapngFile).Length / 1MB, 2)
Write-Host "[+] pcapng generado: $pcapSize MiB"

# ── Conexión TLS ──────────────────────────────────────────────────────
Write-Host "[*] Estableciendo tunel TLS 1.2..."
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient($KALI_IP, $KALI_PORT)
    $tcpClient.SendTimeout = 180000
    $netStream  = $tcpClient.GetStream()
    $certCB     = [System.Net.Security.RemoteCertificateValidationCallback] { return $true }
    $sslStream  = New-Object System.Net.Security.SslStream($netStream, $false, $certCB)
    $sslStream.AuthenticateAsClient($KALI_IP, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
    Write-Host "[+] TLS 1.2 establecido"
} catch {
    Remove-Item -Force $etlFile, $pcapngFile -ErrorAction SilentlyContinue
    Write-Error "[-] Error TLS: $_"; exit 1
}

# ── Streaming con hash en vuelo ───────────────────────────────────────
$sha256       = [System.Security.Cryptography.SHA256]::Create()
$sourceStream = [System.IO.File]::OpenRead($pcapngFile)
$buffer       = New-Object byte[] (64 * 1024)
$totalBytes   = 0

try {
    while (($n = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $sha256.TransformBlock($buffer, 0, $n, $null, 0) | Out-Null
        $sslStream.Write($buffer, 0, $n)
        $sslStream.Flush()
        $totalBytes += $n
        Write-Host -NoNewline "`r[*] Transferidos: $([math]::Round($totalBytes / 1MB, 2)) MiB"
    }
} finally {
    $sourceStream.Close(); $sslStream.Close(); $tcpClient.Close()
}

$sha256.TransformFinalBlock(@(), 0, 0) | Out-Null
$finalHash = ([BitConverter]::ToString($sha256.Hash)).Replace("-", "")

# ── Limpieza ──────────────────────────────────────────────────────────
Write-Host "`n[*] Eliminando archivos temporales..."
Remove-Item -Force $etlFile, $pcapngFile -ErrorAction SilentlyContinue
$remaining = @($etlFile, $pcapngFile) | Where-Object { Test-Path $_ }
if ($remaining.Count -eq 0) { Write-Host "[+] Temporales eliminados" }
else { Write-Host "[!] No eliminados: $($remaining -join ', ')" }

Write-Host "[+] SHA256 Origen     : $finalHash"
Write-Host "[!] Verificar en Kali : sha256sum captura.pcapng"
Write-Host "[!] Analizar en Kali  : wireshark captura.pcapng"
```

---

## Script C — Volcado del registro (SAM, SYSTEM, SOFTWARE)

**Orden de ejecución:** 3  |  **Archivo:** `scripts/ScriptC_Registro.ps1`

Vuelca los *hives* del registro con `reg save` y los empaqueta en un ZIP junto a un **manifest de
cadena de custodia**. Puntos forenses clave: (1) calcula un **SHA-256 individual por hive** *antes* de
comprimir, para poder probar la integridad de SAM por separado sin descomprimir ni confiar en el hash del
contenedor; (2) el manifest (hostname, usuario, timestamp, hashes) viaja **dentro** del ZIP; (3) un bloque
`try/finally` **garantiza la limpieza** de los `.hiv` incluso ante error o Ctrl+C — crítico, porque esos
hives contienen hashes NTLM y no deben quedar huérfanos en disco.

**Requisitos:** PowerShell como Administrador.
**Receptor Kali:** `ncat --ssl ... -l 4445 > registro.zip`

```powershell
# =====================================================================
#  SCRIPT C  |  Volcado del Registro de Windows (SAM, SYSTEM, SOFTWARE)
#  Orden de ejecución : 3°
#  Puerto Kali        : 4445
#  Privilegios        : Administrador elevado requerido
# =====================================================================
#  Kali (ejecutar ANTES):
#    ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -l 4445 > registro.zip
#  Verificar hives individualmente:
#    unzip registro.zip && sha256sum SAM_*.hiv SYSTEM_*.hiv SOFTWARE_*.hiv
#    diff <(sha256sum SAM_*.hiv | awk '{print $1}') <(grep SAM manifest*.txt | awk '{print $NF}')
# =====================================================================

param(
    [string]$KALI_IP  = "20.0.0.2",
    [int]$KALI_PORT   = 4445,
    [string]$TempDir  = $env:TEMP
)
$ErrorActionPreference = "Stop"

$ts           = Get-Date -Format "ddMMyyyy_HHmm"
$samFile      = Join-Path $TempDir "SAM_${ts}.hiv"
$sysFile      = Join-Path $TempDir "SYSTEM_${ts}.hiv"
$swFile       = Join-Path $TempDir "SOFTWARE_${ts}.hiv"
$manifestFile = Join-Path $TempDir "manifest_${ts}.txt"
$zipFile      = Join-Path $TempDir "registro_${ts}.zip"

# Lista completa para el bloque finally
$allTempFiles = @($samFile, $sysFile, $swFile, $manifestFile, $zipFile)

Write-Host "========================================================="
Write-Host " ADQUISICION FORENSE - REGISTRO WINDOWS (SCRIPT C - 3ro)"
Write-Host "========================================================="
Write-Host "[*] Destino : $KALI_IP : $KALI_PORT"
Write-Host "[*] Hives   : SAM, SYSTEM, SOFTWARE"

# ── Verificar Admin ───────────────────────────────────────────────────
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[-] Requiere PowerShell ejecutado como Administrador"
    exit 1
}
Write-Host "[+] Privilegios de Administrador verificados"

# ── [FIX CRÍTICO] try/finally garantiza limpieza incluso si hay errores ──
# Sin esto, cualquier fallo deja archivos .hiv con hashes NTLM en disco.
try {

    # ── Volcar hives ──────────────────────────────────────────────────
    Write-Host "[*] Volcando SAM..."
    $r = & reg save "HKLM\SAM" $samFile /y 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Error volcando SAM: $r" }

    Write-Host "[*] Volcando SYSTEM..."
    $r = & reg save "HKLM\SYSTEM" $sysFile /y 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Error volcando SYSTEM: $r" }

    Write-Host "[*] Volcando SOFTWARE (el más grande, puede tardar)..."
    $r = & reg save "HKLM\SOFTWARE" $swFile /y 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Error volcando SOFTWARE: $r" }

    Write-Host "[+] Hives volcados:"
    Write-Host "    SAM     : $([math]::Round((Get-Item $samFile).Length / 1MB, 2)) MiB"
    Write-Host "    SYSTEM  : $([math]::Round((Get-Item $sysFile).Length / 1MB, 2)) MiB"
    Write-Host "    SOFTWARE: $([math]::Round((Get-Item $swFile ).Length / 1MB, 2)) MiB"

    # ── [FIX CRÍTICO] Hash individual por hive ANTES de comprimir ────
    # El SHA-256 del ZIP no sirve para verificar un hive por separado.
    # Un investigador necesita poder probar la integridad de SAM sin
    # descomprimir y sin confiar en el hash del contenedor.
    Write-Host "[*] Calculando hashes individuales..."
    $hashSAM = (Get-FileHash $samFile  -Algorithm SHA256).Hash
    $hashSYS = (Get-FileHash $sysFile  -Algorithm SHA256).Hash
    $hashSW  = (Get-FileHash $swFile   -Algorithm SHA256).Hash

    Write-Host "[+] SHA256 SAM     : $hashSAM"
    Write-Host "[+] SHA256 SYSTEM  : $hashSYS"
    Write-Host "[+] SHA256 SOFTWARE: $hashSW"

    # ── Manifest de cadena de custodia dentro del ZIP ─────────────────
    # El manifest viaja junto a los hives para que el receptor pueda
    # verificar cada archivo individualmente sin consultar esta consola.
    $manifestContent = @"
==========================================================
 MANIFEST DE CADENA DE CUSTODIA — REGISTRO DE WINDOWS
 Capturado : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
 Hostname   : $env:COMPUTERNAME
 Usuario    : $env:USERNAME
==========================================================
SHA256 SAM      : $hashSAM
SHA256 SYSTEM   : $hashSYS
SHA256 SOFTWARE : $hashSW
==========================================================
Verificar en Kali:
  unzip registro.zip
  sha256sum SAM_${ts}.hiv     -> debe coincidir con SHA256 SAM
  sha256sum SYSTEM_${ts}.hiv  -> debe coincidir con SHA256 SYSTEM
  sha256sum SOFTWARE_${ts}.hiv-> debe coincidir con SHA256 SOFTWARE
"@
    $manifestContent | Out-File -FilePath $manifestFile -Encoding UTF8

    # ── Comprimir hives + manifest en ZIP ─────────────────────────────
    Write-Host "[*] Comprimiendo en ZIP..."
    Compress-Archive -Path $samFile, $sysFile, $swFile, $manifestFile `
                     -DestinationPath $zipFile -Force
    $zipSize = [math]::Round((Get-Item $zipFile).Length / 1MB, 2)
    Write-Host "[+] ZIP generado: $zipSize MiB"

    # ── Conexión TLS ──────────────────────────────────────────────────
    Write-Host "[*] Estableciendo tunel TLS 1.2..."
    $tcpClient = New-Object System.Net.Sockets.TcpClient($KALI_IP, $KALI_PORT)
    $tcpClient.SendTimeout = 0        # Sin límite — SOFTWARE puede ser grande
    $netStream  = $tcpClient.GetStream()
    $certCB     = [System.Net.Security.RemoteCertificateValidationCallback] { return $true }
    $sslStream  = New-Object System.Net.Security.SslStream($netStream, $false, $certCB)
    $sslStream.AuthenticateAsClient($KALI_IP, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
    Write-Host "[+] TLS 1.2 establecido"

    # ── Streaming con hash en vuelo (hash del ZIP = integridad de transferencia) ─
    $sha256       = [System.Security.Cryptography.SHA256]::Create()
    $sourceStream = [System.IO.File]::OpenRead($zipFile)
    $buffer       = New-Object byte[] (64 * 1024)
    $totalBytes   = 0

    try {
        while (($n = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $sha256.TransformBlock($buffer, 0, $n, $null, 0) | Out-Null
            $sslStream.Write($buffer, 0, $n)
            $sslStream.Flush()
            $totalBytes += $n
            Write-Host -NoNewline "`r[*] Transferidos: $([math]::Round($totalBytes / 1MB, 1)) MiB"
        }
    } finally {
        $sourceStream.Close(); $sslStream.Close(); $tcpClient.Close()
    }

    $sha256.TransformFinalBlock(@(), 0, 0) | Out-Null
    $zipHash = ([BitConverter]::ToString($sha256.Hash)).Replace("-", "")

    Write-Host "`n"
    Write-Host "[+] === RESUMEN DE HASHES PARA EL INFORME ==="
    Write-Host "[+] SHA256 SAM          : $hashSAM"
    Write-Host "[+] SHA256 SYSTEM       : $hashSYS"
    Write-Host "[+] SHA256 SOFTWARE     : $hashSW"
    Write-Host "[+] SHA256 ZIP (tránsito): $zipHash"
    Write-Host "[!] Verificar en Kali   : sha256sum registro.zip  (debe = SHA256 ZIP)"

} finally {
    # [FIX CRÍTICO] Este bloque se ejecuta SIEMPRE: en éxito, en error,
    # en Ctrl+C. Los .hiv con hashes NTLM no quedan huérfanos en disco.
    Write-Host "`n[*] Limpieza de archivos temporales (finally)..."
    foreach ($f in $allTempFiles) {
        if (Test-Path $f) {
            Remove-Item -Force $f -ErrorAction SilentlyContinue
            if (Test-Path $f) { Write-Host "[!] No eliminado: $f" }
            else              { Write-Host "[+] Eliminado   : $f" }
        }
    }
}
```

---

## Script D — Imagen cruda de disco (dd.exe)

**Orden de ejecución:** 4 · el menos volátil  |  **Archivo:** `scripts/ScriptD_Disco.ps1`

Adquiere una **imagen forense cruda** del disco físico con `dd.exe`, transmitida **directo por TLS**
sin tocar el disco de la víctima (*fileless*). Es el último paso (el disco es lo menos volátil). Incluye
un **pre-flight** que valida que `dd.exe` realmente escribe a `STDOUT` (con un archivo de prueba de 512
bytes), para no enviar “cero bytes con hash de archivo vacío” en silencio; hash SHA-256 en vuelo; métricas
de velocidad (MiB/s, Stopwatch para no penalizar la transferencia); y aviso si `dd` sale con código de
error (imagen potencialmente incompleta). La imagen resultante se importa en Kali con Autopsy como
*Raw/DD Image*.

**Requisitos:** `dd.exe` (versión chrysocome.net) en el directorio, Administrador.
**Receptor Kali:** `ncat --ssl ... -l 4446 > disco.raw`

```powershell
# =====================================================================
#  SCRIPT D  |  Adquisición de Imagen de Disco Crudo (dd.exe)
#  Orden de ejecución : 4° (ÚLTIMO — el disco es lo menos volátil)
#  Puerto Kali        : 4446
#  Herramienta        : dd.exe para Windows (versión chrysocome.net)
#  Impacto en disco   : CERO — imagen viaja directo por TLS (fileless)
# =====================================================================
#  Kali (ejecutar ANTES):
#    ncat --ssl --ssl-cert cert.pem --ssl-key key.pem -l 4446 > disco.raw
#  Verificar:
#    sha256sum disco.raw   (comparar con hash impreso al finalizar)
#    autopsy               (importar como "Raw/DD Image")
# =====================================================================

param(
    [string]$KALI_IP    = "20.0.0.2",
    [int]$KALI_PORT     = 4446,
    [string]$DdPath     = ".\dd.exe",
    [string]$Drive      = "\\.\PhysicalDrive0",
    [int]$BlockSizeKB   = 64
)
$ErrorActionPreference = "Stop"

if (-not (Test-Path $DdPath)) {
    Write-Error "[-] No encontrado: $DdPath`n    Colocar dd.exe en: $((Resolve-Path '.').Path)"
    exit 1
}

$blockBytes = [long]$BlockSizeKB * 1024
$timestamp  = Get-Date -Format "ddMMyyyy-HHmm"

Write-Host "========================================================="
Write-Host " ADQUISICION FORENSE - IMAGEN DE DISCO (SCRIPT D - 4to)"
Write-Host " ULTIMO EN EJECUTARSE"
Write-Host "========================================================="
Write-Host "[*] Destino    : $KALI_IP : $KALI_PORT"
Write-Host "[*] Fuente     : $Drive"
Write-Host "[*] Block size : $BlockSizeKB KiB"
Write-Host "[!] FILELESS   : la imagen NO toca el disco de la víctima"

# ── [FIX CRÍTICO] Pre-flight: validar que dd.exe escribe en stdout ────
# El comportamiento de dd sin "of=" no está garantizado en todas las
# versiones Windows. Si no escribe a stdout, enviamos cero bytes con
# un hash de "archivo vacío" sin ningún error visible.
# Usamos un archivo temporal de 512 bytes como prueba — no tocamos el disco.
Write-Host "[*] Pre-flight: validando que dd.exe escribe en stdout..."
$testFile = Join-Path $env:TEMP "dd_pretest_$timestamp.bin"
try {
    [System.IO.File]::WriteAllBytes($testFile, (New-Object byte[] 512))

    $testInfo = New-Object System.Diagnostics.ProcessStartInfo
    $testInfo.FileName               = $DdPath
    $testInfo.Arguments              = "if=$testFile bs=512 count=1"
    $testInfo.UseShellExecute        = $false
    $testInfo.RedirectStandardOutput = $true
    $testInfo.CreateNoWindow         = $true  # [FIX] Sin ventana visible
    $testProc = [System.Diagnostics.Process]::Start($testInfo)

    $testBuf  = New-Object byte[] 512
    $testRead = $testProc.StandardOutput.BaseStream.Read($testBuf, 0, 512)
    $testProc.WaitForExit()

    if ($testRead -eq 0) {
        Write-Error "[-] dd.exe NO escribe en stdout. Probar con argumento 'of=-' o verificar version."
        exit 1
    }
    Write-Host "[+] Pre-flight OK: dd.exe escribe en stdout ($testRead bytes leídos)"
} finally {
    Remove-Item -Force $testFile -ErrorAction SilentlyContinue
}

# ── Conexión TLS ──────────────────────────────────────────────────────
Write-Host "[*] Estableciendo tunel TLS 1.2..."
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient($KALI_IP, $KALI_PORT)
    $tcpClient.SendTimeout    = 0
    $tcpClient.ReceiveTimeout = 0
    $netStream  = $tcpClient.GetStream()
    $certCB     = [System.Net.Security.RemoteCertificateValidationCallback] { return $true }
    $sslStream  = New-Object System.Net.Security.SslStream($netStream, $false, $certCB)
    $sslStream.AuthenticateAsClient($KALI_IP, $null, [System.Security.Authentication.SslProtocols]::Tls12, $false)
    Write-Host "[+] TLS 1.2 establecido"
} catch { Write-Error "[-] Error TLS: $_"; exit 1 }

# ── Lanzar dd.exe ─────────────────────────────────────────────────────
$ddInfo = New-Object System.Diagnostics.ProcessStartInfo
$ddInfo.FileName               = $DdPath
$ddInfo.Arguments              = "if=$Drive bs=$blockBytes"
$ddInfo.UseShellExecute        = $false
$ddInfo.RedirectStandardOutput = $true
$ddInfo.RedirectStandardError  = $false  # stderr de dd → consola (progreso visible)
$ddInfo.CreateNoWindow         = $true   # [FIX] Sin ventana en el escritorio víctima

$ddProc = New-Object System.Diagnostics.Process
$ddProc.StartInfo = $ddInfo
$ddProc.Start() | Out-Null
Write-Host "[+] dd.exe iniciado (PID: $($ddProc.Id))"

$sourceStream = $ddProc.StandardOutput.BaseStream

# ── Streaming con hash en vuelo ───────────────────────────────────────
$sha256     = [System.Security.Cryptography.SHA256]::Create()
$buffer     = New-Object byte[] ($blockBytes)
$totalBytes = [long]0
$startTime  = [System.Diagnostics.Stopwatch]::StartNew()
$blockCount = 0

# [FIX] Get-Date por cada bloque en un disco de 100 GB = ~1.6 M llamadas.
# Usar Stopwatch (acceso nativo, microsegundos) y actualizar pantalla
# cada 200 bloques (cada ~12 MB con bs=64K) para no penalizar la transferencia.
try {
    while (($n = $sourceStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $sha256.TransformBlock($buffer, 0, $n, $null, 0) | Out-Null
        $sslStream.Write($buffer, 0, $n)
        $sslStream.Flush()
        $totalBytes += $n
        $blockCount++

        if ($blockCount % 200 -eq 0) {
            $elapsedSec = $startTime.Elapsed.TotalSeconds
            $mbps = if ($elapsedSec -gt 0) { [math]::Round(($totalBytes / 1MB) / $elapsedSec, 1) } else { 0 }
            Write-Host -NoNewline "`r[*] $([math]::Round($totalBytes / 1GB, 3)) GiB  |  $mbps MiB/s  "
        }
    }
} finally {
    $sourceStream.Close()
    $ddProc.WaitForExit()
    $sslStream.Close()
    $tcpClient.Close()
    $startTime.Stop()
}

$sha256.TransformFinalBlock(@(), 0, 0) | Out-Null
$finalHash  = ([BitConverter]::ToString($sha256.Hash)).Replace("-", "")
$minTotal   = [math]::Round($startTime.Elapsed.TotalMinutes, 1)
$avgMBps    = if ($startTime.Elapsed.TotalSeconds -gt 0) { [math]::Round(($totalBytes / 1MB) / $startTime.Elapsed.TotalSeconds, 1) } else { 0 }

Write-Host "`n"
Write-Host "[+] Adquisición completada"
Write-Host "[+] Total transferido    : $([math]::Round($totalBytes / 1GB, 3)) GiB"
Write-Host "[+] Tiempo total         : $minTotal minutos"
Write-Host "[+] Velocidad promedio   : $avgMBps MiB/s"
Write-Host "[+] SHA256 Origen        : $finalHash"
Write-Host "[!] Verificar en Kali    : sha256sum disco.raw"
Write-Host "[!] Analizar en Kali     : autopsy  (importar como Raw/DD Image)"

if ($ddProc.ExitCode -ne 0) {
    Write-Host "[!] ADVERTENCIA: dd.exe salió con código $($ddProc.ExitCode)."
    Write-Host "[!] La imagen puede estar incompleta (sectores defectuosos o disco más grande que lo transferido)."
}
```

---

## Verificación de integridad (en Kali)

Tras recibir cada archivo, se compara el hash impreso por el script (origen) con el del archivo recibido:

```bash
sha256sum ram.mem red_config.txt captura.pcapng registro.zip disco.raw
# cada valor debe coincidir con el 'SHA256 Origen' que imprimió el script correspondiente
```

Para el registro, además, se verifica cada hive por separado contra el manifest incluido en el ZIP.

---

*Trabajo de laboratorio en entorno aislado, con fines defensivos y educativos (DFIR). No contiene
malware ni instrucciones ofensivas.*

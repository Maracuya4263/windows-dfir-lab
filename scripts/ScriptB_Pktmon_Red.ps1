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

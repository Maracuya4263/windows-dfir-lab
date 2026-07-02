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
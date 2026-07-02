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

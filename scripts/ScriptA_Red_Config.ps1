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

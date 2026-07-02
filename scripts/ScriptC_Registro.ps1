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

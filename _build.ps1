# _build.ps1 — Compilador SecuritySuite
# Genera icono + EXE con PS2EXE

Set-Location $PSScriptRoot

# Verificar sintaxis antes de compilar
Write-Host "Verificando sintaxis..." -ForegroundColor Cyan
$content = Get-Content ".\SecuritySuite.ps1" -Raw
$errors  = $null
[System.Management.Automation.PSParser]::Tokenize($content, [ref]$errors) | Out-Null
if ($errors.Count -gt 0) {
    Write-Host "ERRORES DE SINTAXIS:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  L$($_.Token.StartLine): $($_.Message)" -ForegroundColor Red }
    exit 1
}
Write-Host "Sintaxis OK (0 errores)" -ForegroundColor Green

# Instalar PS2EXE si no esta disponible
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "Instalando PS2EXE..." -ForegroundColor Yellow
    Install-Module ps2exe -Scope CurrentUser -Force -AllowClobber
}

# Generar icono — escudo moderno con candado
Write-Host "Generando icono..." -ForegroundColor Cyan
Add-Type -AssemblyName System.Drawing

# Crear en 256x256 para calidad, luego redimensionar a 48x48 para .ico
$hi  = New-Object System.Drawing.Bitmap(256, 256)
$g   = [System.Drawing.Graphics]::FromImage($hi)
$g.SmoothingMode   = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.TextRenderingHint = [System.Drawing.Text.TextRenderingHint]::AntiAlias
$g.Clear([System.Drawing.Color]::FromArgb(10, 10, 26))

# Fondo circular
$bgBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(28, 28, 48))
$g.FillEllipse($bgBrush, 10, 10, 236, 236)
$bgBrush.Dispose()

# Escudo — forma clasica con bezier (top rounded, bottom pointed)
$sp = New-Object System.Drawing.Drawing2D.GraphicsPath
$sp.AddBezier(
    [System.Drawing.PointF]::new(128,  30),   # top-center
    [System.Drawing.PointF]::new(200,  30),   # control top-right
    [System.Drawing.PointF]::new(215,  80),   # control right-top
    [System.Drawing.PointF]::new(215, 120)    # right-mid
)
$sp.AddBezier(
    [System.Drawing.PointF]::new(215, 120),
    [System.Drawing.PointF]::new(215, 170),
    [System.Drawing.PointF]::new(175, 200),
    [System.Drawing.PointF]::new(128, 226)    # bottom-tip
)
$sp.AddBezier(
    [System.Drawing.PointF]::new(128, 226),
    [System.Drawing.PointF]::new(81,  200),
    [System.Drawing.PointF]::new(41,  170),
    [System.Drawing.PointF]::new(41,  120)
)
$sp.AddBezier(
    [System.Drawing.PointF]::new(41,  120),
    [System.Drawing.PointF]::new(41,   80),
    [System.Drawing.PointF]::new(56,   30),
    [System.Drawing.PointF]::new(128,  30)
)
$sp.CloseFigure()

# Fill escudo — gradiente oscuro rojo
$gradBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    [System.Drawing.Point]::new(128, 30),
    [System.Drawing.Point]::new(128, 226),
    [System.Drawing.Color]::FromArgb(120, 30, 30),
    [System.Drawing.Color]::FromArgb(60, 10, 10)
)
$g.FillPath($gradBrush, $sp)
$gradBrush.Dispose()

# Borde del escudo
$borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 68, 68), 4)
$g.DrawPath($borderPen, $sp)
$borderPen.Dispose(); $sp.Dispose()

# Candado — arco (shackle) parte superior
$shacklePen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 14)
$shacklePen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
$shacklePen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
$g.DrawArc($shacklePen, 90, 80, 76, 76, 180, 180)
$shacklePen.Dispose()

# Cuerpo del candado
$bodyBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White)
$g.FillRectangle($bodyBrush, 88, 128, 80, 62)
$bodyBrush.Dispose()
# Interior oscuro del cuerpo
$innerBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30,30,50))
$g.FillRectangle($innerBrush, 96, 136, 64, 46)
$innerBrush.Dispose()

# Agujero de la cerradura
$g.FillEllipse([System.Drawing.Brushes]::White, 115, 144, 26, 26)
$dotBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(30,30,50))
$g.FillEllipse($dotBrush, 120, 149, 16, 16)
$dotBrush.Dispose()

$g.Dispose()

# Redimensionar a 48x48
$bmp = New-Object System.Drawing.Bitmap(48, 48)
$gs  = [System.Drawing.Graphics]::FromImage($bmp)
$gs.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$gs.DrawImage($hi, 0, 0, 48, 48)
$gs.Dispose(); $hi.Dispose()

# Convertir a ICO
$icon = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
$fs   = [System.IO.File]::OpenWrite("$PSScriptRoot\icon.ico")
$icon.Save($fs)
$fs.Close()
$icon.Dispose()
$bmp.Dispose()
Write-Host "Icono generado: icon.ico" -ForegroundColor Green

# Compilar
Write-Host "Compilando SecuritySuite.exe..." -ForegroundColor Cyan
Import-Module ps2exe
Invoke-ps2exe `
    -inputFile  "$PSScriptRoot\SecuritySuite.ps1" `
    -outputFile "$PSScriptRoot\SecuritySuite.exe" `
    -iconFile   "$PSScriptRoot\icon.ico" `
    -noConsole  `
    -title      "SecuritySuite" `
    -description "Suite de seguridad y privacidad para Windows" `
    -company    "EnMaNueL-G" `
    -version    "1.0.1.0"

if (Test-Path "$PSScriptRoot\SecuritySuite.exe") {
    $size = [Math]::Round((Get-Item "$PSScriptRoot\SecuritySuite.exe").Length / 1KB, 0)
    Write-Host "EXE generado: SecuritySuite.exe ($size KB)" -ForegroundColor Green

    # Crear ZIP
    $zipPath = "$PSScriptRoot\SecuritySuite-v1.0.1.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path "$PSScriptRoot\SecuritySuite.exe","$PSScriptRoot\SecuritySuite.bat" -DestinationPath $zipPath
    $zipSize = [Math]::Round((Get-Item $zipPath).Length / 1KB, 0)
    Write-Host "ZIP generado: SecuritySuite-v1.0.0.zip ($zipSize KB)" -ForegroundColor Green
} else {
    Write-Host "ERROR: No se genero el EXE" -ForegroundColor Red
    exit 1
}

Write-Host "`nBuild completado exitosamente." -ForegroundColor Green

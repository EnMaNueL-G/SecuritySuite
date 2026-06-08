#Requires -Version 5.1
<#
  SecuritySuite v1.0.0
  Suite de seguridad y privacidad para Windows 10/11
  Enmanuel Gil — https://github.com/EnMaNueL-G
  Sin ads | Sin telemetria | Codigo abierto | Gratuito

  FUNCIONES:
    - Desactivar telemetria de Windows (servicios + tareas programadas)
    - Auditor de inicio: lista, clasifica y controla programas de inicio
    - Limpiador de rastros: temp, cache, MRU, prefetch, papelera
    - Gestor de Firewall: bloquear/desbloquear apps del acceso a red
    - Puntuacion de seguridad en tiempo real (0-100)
#>

Set-StrictMode -Off
$ErrorActionPreference = 'SilentlyContinue'

# ── Ruta de la aplicacion ─────────────────────────────────────────────────────
if ($PSScriptRoot -and $PSScriptRoot -ne '') {
    $script:AppDir = $PSScriptRoot
} else {
    try   { $script:AppDir = Split-Path -Parent ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) }
    catch { $script:AppDir = $env:TEMP }
}

# ── Assemblies ────────────────────────────────────────────────────────────────
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# ── Privilegios de administrador ──────────────────────────────────────────────
$script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# ── Datos: servicios de telemetria ────────────────────────────────────────────
$script:TelSvcs = @(
    [pscustomobject]@{ Name='DiagTrack';      Desc='Experiencias de usuario conectadas — telemetria principal'; Risk='Alto'  }
    [pscustomobject]@{ Name='dmwappushsvc';   Desc='Enrutamiento WAP Push — telemetria de mensajeria';          Risk='Alto'  }
    [pscustomobject]@{ Name='WerSvc';         Desc='Servicio de informes de errores de Windows';                Risk='Medio' }
    [pscustomobject]@{ Name='XblAuthManager'; Desc='Xbox Live Auth — innecesario sin Xbox';                     Risk='Bajo'  }
    [pscustomobject]@{ Name='XblGameSave';    Desc='Xbox Live Game Save — innecesario sin Xbox';                Risk='Bajo'  }
    [pscustomobject]@{ Name='XboxNetApiSvc';  Desc='Xbox Live Networking — innecesario sin Xbox';               Risk='Bajo'  }
    [pscustomobject]@{ Name='MapsBroker';     Desc='Actualizacion automatica de mapas de Microsoft';            Risk='Bajo'  }
)

# ── Datos: tareas programadas de telemetria ───────────────────────────────────
$script:TelTasks = @(
    [pscustomobject]@{ Path='\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser'; Short='Compat Appraiser';   Desc='Analiza apps y envia datos de compatibilidad a MS';          Risk='Alto'  }
    [pscustomobject]@{ Path='\Microsoft\Windows\Application Experience\ProgramDataUpdater';               Short='Program Updater';    Desc='Actualiza base de datos de compatibilidad de programas';     Risk='Medio' }
    [pscustomobject]@{ Path='\Microsoft\Windows\Autochk\Proxy';                                           Short='Autochk Proxy';      Desc='Envia informacion de estado del disco a Microsoft';          Risk='Medio' }
    [pscustomobject]@{ Path='\Microsoft\Windows\Customer Experience Improvement Program\Consolidator';    Short='CEIP Consolidator';  Desc='Programa de mejora de experiencia — telemetria principal';   Risk='Alto'  }
    [pscustomobject]@{ Path='\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask';  Short='Kernel CEIP';        Desc='Telemetria a nivel de kernel del sistema operativo';         Risk='Alto'  }
    [pscustomobject]@{ Path='\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip';        Short='USB CEIP';           Desc='Datos de dispositivos USB conectados enviados a MS';         Risk='Medio' }
    [pscustomobject]@{ Path='\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector'; Short='Disk Diagnostic'; Desc='Diagnostico de disco — datos enviados a Microsoft';      Risk='Medio' }
    [pscustomobject]@{ Path='\Microsoft\Windows\Windows Error Reporting\QueueReporting';                 Short='WER Queue';          Desc='Envia informes de errores acumulados a Microsoft';           Risk='Medio' }
    [pscustomobject]@{ Path='\Microsoft\Windows\Feedback\Siuf\DmClient';                                 Short='Feedback Client';    Desc='Envia respuestas de encuestas de retroalimentacion a MS';   Risk='Bajo'  }
)

# ── Datos: recomendaciones de inicio ─────────────────────────────────────────
$script:kSystem      = @('ctfmon','sihost','taskhostw','runtimebroker','searchindexer','dwm','winlogon','lsass','explorer','audiodg')
$script:kNonEssential= @('onedrive','teams','microsoftteams','discord','spotify','steam','epicgameslauncher','adobegc','skype','zoom','slack','dropbox','googledrivefs','opera','brave','googlechrome','msedge','firefox','whatsapp','telegram')
$script:kReview      = @('nvcplui','amdrsserv','igcc','intelcphs','realtekcom','razerprocmon','corsair','logichoptions','synapse','nahimic','dts','steelseries')

# ── Datos: categorias del limpiador ──────────────────────────────────────────
$script:CleanCats = @(
    [pscustomobject]@{ Id='UserTemp';  Name='Temporales de usuario';     Desc='%TEMP% — archivos temporales del perfil actual';                    Path=$env:TEMP;                                                                                     Admin=$false; Checked=$true  }
    [pscustomobject]@{ Id='SysTemp';   Name='Temporales del sistema';    Desc='C:\Windows\Temp — requiere administrador';                          Path='C:\Windows\Temp';                                                                             Admin=$true;  Checked=$true  }
    [pscustomobject]@{ Id='Thumbs';    Name='Cache de miniaturas';       Desc='Miniaturas en cache del Explorador (se regeneran solas)';            Path=[IO.Path]::Combine($env:LOCALAPPDATA,'Microsoft','Windows','Explorer');                        Admin=$false; Checked=$true  }
    [pscustomobject]@{ Id='INetCache'; Name='Cache Internet / Edge';     Desc='Cache de Edge, IE y WebView2';                                       Path=[IO.Path]::Combine($env:LOCALAPPDATA,'Microsoft','Windows','INetCache');                       Admin=$false; Checked=$true  }
    [pscustomobject]@{ Id='Recent';    Name='Archivos recientes (MRU)';  Desc='Historial de archivos abiertos recientemente en el Explorador';      Path=[IO.Path]::Combine($env:APPDATA,'Microsoft','Windows','Recent');                             Admin=$false; Checked=$false }
    [pscustomobject]@{ Id='Prefetch';  Name='Prefetch';                  Desc='Cache de precarga de apps — requiere administrador';                  Path='C:\Windows\Prefetch';                                                                         Admin=$true;  Checked=$false }
    [pscustomobject]@{ Id='WinUpd';    Name='Cache de Windows Update';   Desc='Instaladores ya aplicados — puede liberar GBs — req. admin';         Path='C:\Windows\SoftwareDistribution\Download';                                                   Admin=$true;  Checked=$false }
    [pscustomobject]@{ Id='Recycle';   Name='Papelera de reciclaje';     Desc='Archivos en papelera aun no eliminados definitivamente';             Path='';                                                                                             Admin=$false; Checked=$false }
)

# ── Helper UI ─────────────────────────────────────────────────────────────────
function Get-C($n) { try { $script:window.FindName($n) } catch { $null } }
function On($c,$e,$sb) { if ($null -ne $c) { try { $c."Add_$e"($sb) } catch {} } }
function SafeLog($msg) { try { $l = Get-C 'lblStatus'; if ($l) { $l.Text = [string]$msg } } catch {} }

# ── Funciones: Servicios ──────────────────────────────────────────────────────
function Get-SvcStartType($name) {
    try { return (Get-WmiObject Win32_Service -Filter "Name='$name'" -EA Stop).StartMode }
    catch { return 'NoEncontrado' }
}
function Set-SvcDisabled($name) {
    try { Stop-Service $name -Force -EA Stop; Set-Service $name -StartupType Disabled -EA Stop; return $true }
    catch { return $false }
}
function Set-SvcEnabled($name) {
    try { Set-Service $name -StartupType Manual -EA Stop; return $true }
    catch { return $false }
}

# ── Funciones: Tareas programadas ────────────────────────────────────────────
function Get-TaskStatusStr($path) {
    try {
        $parent = Split-Path $path -Parent
        $leaf   = Split-Path $path -Leaf
        $t = Get-ScheduledTask -TaskPath $parent -TaskName $leaf -EA Stop
        return $t.State.ToString()
    } catch { return 'NoEncontrado' }
}
function Set-TaskDisabled($path) {
    try { Disable-ScheduledTask -TaskPath (Split-Path $path -Parent) -TaskName (Split-Path $path -Leaf) -EA Stop; return $true }
    catch { return $false }
}
function Set-TaskEnabled($path) {
    try { Enable-ScheduledTask -TaskPath (Split-Path $path -Parent) -TaskName (Split-Path $path -Leaf) -EA Stop; return $true }
    catch { return $false }
}

# ── Funciones: Inicio de Windows ─────────────────────────────────────────────
function Get-StartupRec($name) {
    $n = $name.ToLower()
    foreach ($k in $script:kSystem)       { if ($n -like "*$k*") { return @{ Text='Sistema';     Color='#3498DB' } } }
    foreach ($k in $script:kNonEssential) { if ($n -like "*$k*") { return @{ Text='No esencial'; Color='#E67E22' } } }
    foreach ($k in $script:kReview)       { if ($n -like "*$k*") { return @{ Text='Revisar';     Color='#F39C12' } } }
    return @{ Text='Desconocido'; Color='#7F8C8D' }
}
function Get-StartupEnabled($source, $name) {
    $ap = if ($source -eq 'HKCU') { 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
          else                     { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    try { $b = (Get-ItemProperty -Path $ap -Name $name -EA Stop).$name; if ($b) { return $b[0] -eq 2 } }
    catch {}
    return $true
}
function Set-StartupEnabled($source, $name, $enabled) {
    $ap = if ($source -eq 'HKCU') { 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
          else                     { 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run' }
    $bytes = if ($enabled) { [byte[]](2,0,0,0,0,0,0,0,0,0,0,0) } else { [byte[]](3,0,0,0,0,0,0,0,0,0,0,0) }
    try { Set-ItemProperty -Path $ap -Name $name -Value $bytes -Type Binary -EA Stop; return $true }
    catch { return $false }
}
function Get-AllStartupItems() {
    $items = [System.Collections.Generic.List[hashtable]]::new()
    foreach ($rp in @(@{H='HKCU';P='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'},@{H='HKLM';P='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'})) {
        try {
            $props = Get-ItemProperty -Path $rp.P -EA Stop
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                $items.Add(@{ Name=$_.Name; Command=[string]$_.Value; Source=$rp.H; Enabled=(Get-StartupEnabled $rp.H $_.Name) })
            }
        } catch {}
    }
    foreach ($sf in @("$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup","C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")) {
        if (Test-Path $sf) {
            Get-ChildItem $sf -File -EA SilentlyContinue | ForEach-Object {
                $items.Add(@{ Name=$_.BaseName; Command=$_.FullName; Source='Carpeta'; Enabled=$true })
            }
        }
    }
    return $items
}

# ── Funciones: Limpiador ──────────────────────────────────────────────────────
$script:sizeLbls    = @{}
$script:cleanerCBs  = @{}

function Get-FolderSizeMB($path) {
    if (-not $path -or -not (Test-Path $path)) { return 0.0 }
    try { return [Math]::Round(((Get-ChildItem $path -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum) / 1MB, 1) }
    catch { return 0.0 }
}
function Get-RecycleSizeMB() {
    try { return [Math]::Round(((Get-ChildItem 'C:\$Recycle.Bin' -Recurse -Force -EA SilentlyContinue | Measure-Object -Property Length -Sum -EA SilentlyContinue).Sum) / 1MB, 1) }
    catch { return 0.0 }
}

# ── Funciones: Firewall ───────────────────────────────────────────────────────
function Get-SSFWRules() {
    try {
        return @(Get-NetFirewallRule -Action Block -Direction Outbound -EA SilentlyContinue |
            Where-Object { $_.Enabled -eq 'True' -and $_.DisplayName -like 'SS Block:*' } |
            ForEach-Object {
                $app = ($_ | Get-NetFirewallApplicationFilter -EA SilentlyContinue).Program
                [pscustomobject]@{ DisplayName=$_.DisplayName; AppPath=$app }
            })
    } catch { return @() }
}
function Add-SSFWBlock($exePath, $appName) {
    try { New-NetFirewallRule -DisplayName "SS Block: $appName" -Direction Outbound -Action Block -Program $exePath -Enabled True -EA Stop; return $true }
    catch {
        try { netsh advfirewall firewall add rule name="SS Block: $appName" dir=out action=block program=`"$exePath`" enable=yes 2>$null; return ($LASTEXITCODE -eq 0) }
        catch { return $false }
    }
}
function Remove-SSFWBlock($displayName) {
    try { Remove-NetFirewallRule -DisplayName $displayName -EA Stop; return $true }
    catch {
        try { netsh advfirewall firewall delete rule name=`"$displayName`" 2>$null; return $true }
        catch { return $false }
    }
}

# ── Puntuacion de seguridad ───────────────────────────────────────────────────
function Get-SecurityScore() {
    $pts = 0; $max = 0
    foreach ($s in $script:TelSvcs) {
        $w = if ($s.Risk -eq 'Alto') { 4 } elseif ($s.Risk -eq 'Medio') { 2 } else { 1 }
        $max += $w
        if ((Get-SvcStartType $s.Name) -eq 'Disabled') { $pts += $w }
    }
    foreach ($t in $script:TelTasks) {
        $w = if ($t.Risk -eq 'Alto') { 4 } elseif ($t.Risk -eq 'Medio') { 2 } else { 1 }
        $max += $w
        if ((Get-TaskStatusStr $t.Path) -eq 'Disabled') { $pts += $w }
    }
    if ($max -eq 0) { return 50 }
    return [int](($pts / $max) * 100)
}
function Update-Score() {
    try {
        $s = Get-SecurityScore
        $lbl = Get-C 'lblScore'
        if ($lbl) {
            $lbl.Text = "$s"
            $lbl.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString(
                $(if ($s -ge 70) { '#2ECC71' } elseif ($s -ge 40) { '#F39C12' } else { '#FF4444' }))
        }
        $bar = Get-C 'scoreBar'
        if ($bar) { $bar.Value = $s }
    } catch {}
}

# ── Constructores de filas UI ─────────────────────────────────────────────────

function New-TelemetryRow($item, $isTask) {
    $statusRaw = if ($isTask) { Get-TaskStatusStr $item.Path } else { Get-SvcStartType $item.Name }
    $isOff     = $statusRaw -eq 'Disabled' -or $statusRaw -eq 'NoEncontrado'
    $riskClr   = switch ($item.Risk) { 'Alto' { '#E74C3C' } 'Medio' { '#F39C12' } default { '#3498DB' } }
    $stClr     = if ($isOff) { '#2ECC71' } else { '#E74C3C' }
    $stTxt     = if ($isOff) { 'DESACT.' } else { 'ACTIVO' }
    $btnTxt    = if ($isOff) { 'Activar' } else { 'Desactivar' }
    $btnClr    = if ($isOff) { '#1A5E2A' } else { '#7B1A1A' }
    $displayName = if ($isTask) { $item.Short } else { $item.Name }

    $border = New-Object System.Windows.Controls.Border
    $border.Background    = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#0F0F22')
    $border.CornerRadius  = [System.Windows.CornerRadius]::new(4)
    $border.Margin        = [System.Windows.Thickness]::new(0,0,0,4)
    $border.Padding       = [System.Windows.Thickness]::new(0,6,10,6)

    $grid = New-Object System.Windows.Controls.Grid
    # Col 0: barra de riesgo (6px fija), Col 1: contenido (Star), Col 2: boton (Auto)
    $colR = New-Object System.Windows.Controls.ColumnDefinition; $colR.Width = [System.Windows.GridLength]::new(6)
    $colC = New-Object System.Windows.Controls.ColumnDefinition; $colC.Width = [System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)
    $colB = New-Object System.Windows.Controls.ColumnDefinition; $colB.Width = [System.Windows.GridLength]::Auto
    $grid.ColumnDefinitions.Add($colR) | Out-Null
    $grid.ColumnDefinitions.Add($colC) | Out-Null
    $grid.ColumnDefinitions.Add($colB) | Out-Null
    # Risk bar
    $bar2 = New-Object System.Windows.Controls.Border
    $bar2.Background   = [System.Windows.Media.BrushConverter]::new().ConvertFromString($riskClr)
    $bar2.CornerRadius = [System.Windows.CornerRadius]::new(3,0,0,3)
    $bar2.Margin       = [System.Windows.Thickness]::new(0,0,8,0)
    [System.Windows.Controls.Grid]::SetColumn($bar2, 0)

    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    [System.Windows.Controls.Grid]::SetColumn($sp, 1)

    $t1 = New-Object System.Windows.Controls.TextBlock
    $t1.Text       = $displayName
    $t1.FontWeight = [System.Windows.FontWeights]::SemiBold
    $t1.Foreground = [System.Windows.Media.Brushes]::White

    $t2 = New-Object System.Windows.Controls.TextBlock
    $t2.Text        = $item.Desc
    $t2.FontSize    = 10
    $t2.Foreground  = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#888899')
    $t2.TextWrapping = [System.Windows.TextWrapping]::Wrap

    $riskRow = New-Object System.Windows.Controls.StackPanel
    $riskRow.Orientation = [System.Windows.Controls.Orientation]::Horizontal

    $t3 = New-Object System.Windows.Controls.TextBlock
    $t3.Text     = "Riesgo: $($item.Risk)   Estado: "
    $t3.FontSize = 9
    $t3.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#666677')

    $t4 = New-Object System.Windows.Controls.TextBlock
    $t4.Text       = $stTxt
    $t4.FontSize   = 9
    $t4.FontWeight = [System.Windows.FontWeights]::Bold
    $t4.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($stClr)

    $riskRow.Children.Add($t3) | Out-Null
    $riskRow.Children.Add($t4) | Out-Null
    $sp.Children.Add($t1)      | Out-Null
    $sp.Children.Add($t2)      | Out-Null
    $sp.Children.Add($riskRow) | Out-Null

    $btn = New-Object System.Windows.Controls.Button
    $btn.Content         = $btnTxt
    $btn.Padding         = [System.Windows.Thickness]::new(10,3,10,3)
    $btn.FontSize        = 10
    $btn.Background      = [System.Windows.Media.BrushConverter]::new().ConvertFromString($btnClr)
    $btn.Foreground      = [System.Windows.Media.Brushes]::White
    $btn.BorderThickness = [System.Windows.Thickness]::new(0)
    $btn.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $btn.Margin          = [System.Windows.Thickness]::new(8,0,0,0)
    [System.Windows.Controls.Grid]::SetColumn($btn, 2)

    $iCopy = $item; $tCopy = $isTask
    $btn.Add_Click({
        if ($tCopy) {
            if ((Get-TaskStatusStr $iCopy.Path) -eq 'Disabled') { Set-TaskEnabled $iCopy.Path | Out-Null; SafeLog "Activada`: $($iCopy.Short)" }
            else { Set-TaskDisabled $iCopy.Path | Out-Null; SafeLog "Desactivada`: $($iCopy.Short)" }
        } else {
            if ((Get-SvcStartType $iCopy.Name) -eq 'Disabled') { Set-SvcEnabled $iCopy.Name | Out-Null; SafeLog "Activado`: $($iCopy.Name)" }
            else { Set-SvcDisabled $iCopy.Name | Out-Null; SafeLog "Desactivado`: $($iCopy.Name)" }
        }
        Refresh-TelemetryUI
        Update-Score
    }.GetNewClosure())

    $grid.Children.Add($bar2) | Out-Null
    $grid.Children.Add($sp)   | Out-Null
    $grid.Children.Add($btn)  | Out-Null
    $border.Child = $grid
    return $border
}

function Refresh-TelemetryUI() {
    $panel = Get-C 'telemetryList'
    if (-not $panel) { return }
    $panel.Children.Clear()

    foreach ($grp in @(@{Label="SERVICIOS ($($script:TelSvcs.Count))"; Items=$script:TelSvcs; IsTask=$false},
                       @{Label="TAREAS PROGRAMADAS ($($script:TelTasks.Count))"; Items=$script:TelTasks; IsTask=$true})) {
        $hdr = New-Object System.Windows.Controls.TextBlock
        $hdr.Text       = $grp.Label
        $hdr.FontSize   = 10
        $hdr.FontWeight = [System.Windows.FontWeights]::Bold
        $hdr.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#FF4444')
        $hdr.Margin     = [System.Windows.Thickness]::new(0,6,0,4)
        $panel.Children.Add($hdr) | Out-Null
        foreach ($item in $grp.Items) {
            try { $panel.Children.Add((New-TelemetryRow $item $grp.IsTask)) | Out-Null } catch {}
        }
    }
    $info = Get-C 'lblTelemetryInfo'
    if ($info) {
        $info.Text = if ($script:IsAdmin) { 'Ejecutando como administrador — acceso completo' }
                     else { 'Ejecutar como administrador para modificar servicios del sistema' }
    }
}

function New-StartupAuditRow($item) {
    $rec = Get-StartupRec $item.Name
    $en  = $item.Enabled
    $cmd = if ($item.Command.Length -gt 52) { $item.Command.Substring(0,52) + '...' } else { $item.Command }

    $border = New-Object System.Windows.Controls.Border
    $border.Background   = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#0F0F22')
    $border.CornerRadius = [System.Windows.CornerRadius]::new(4)
    $border.Margin       = [System.Windows.Thickness]::new(0,0,0,4)
    $border.Padding      = [System.Windows.Thickness]::new(10,6,10,6)

    $grid = New-Object System.Windows.Controls.Grid
    $c0 = New-Object System.Windows.Controls.ColumnDefinition; $c0.Width = [System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)
    $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = [System.Windows.GridLength]::Auto
    $grid.ColumnDefinitions.Add($c0); $grid.ColumnDefinitions.Add($c1)

    $sp = New-Object System.Windows.Controls.StackPanel
    $sp.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    [System.Windows.Controls.Grid]::SetColumn($sp, 0)

    $row1 = New-Object System.Windows.Controls.StackPanel
    $row1.Orientation = [System.Windows.Controls.Orientation]::Horizontal

    $tn = New-Object System.Windows.Controls.TextBlock
    $tn.Text       = $item.Name
    $tn.FontWeight = [System.Windows.FontWeights]::SemiBold
    $tn.Foreground = if ($en) { [System.Windows.Media.Brushes]::White } else { [System.Windows.Media.BrushConverter]::new().ConvertFromString('#444455') }

    $ts = New-Object System.Windows.Controls.TextBlock
    $ts.Text       = "  [$($item.Source)]"
    $ts.FontSize   = 9
    $ts.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#444455')
    $ts.VerticalAlignment = [System.Windows.VerticalAlignment]::Bottom

    $tr = New-Object System.Windows.Controls.TextBlock
    $tr.Text       = "  $($rec.Text)"
    $tr.FontSize   = 9
    $tr.FontWeight = [System.Windows.FontWeights]::Bold
    $tr.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($rec.Color)
    $tr.VerticalAlignment = [System.Windows.VerticalAlignment]::Bottom

    $row1.Children.Add($tn) | Out-Null
    $row1.Children.Add($ts) | Out-Null
    $row1.Children.Add($tr) | Out-Null

    $tc = New-Object System.Windows.Controls.TextBlock
    $tc.Text       = $cmd
    $tc.FontSize   = 9
    $tc.FontFamily = New-Object System.Windows.Media.FontFamily('Consolas')
    $tc.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#444466')

    $sp.Children.Add($row1) | Out-Null
    $sp.Children.Add($tc)   | Out-Null

    $btn = New-Object System.Windows.Controls.Button
    $btn.Content         = if ($en) { 'Desactivar' } else { 'Activar' }
    $btn.Padding         = [System.Windows.Thickness]::new(8,3,8,3)
    $btn.FontSize        = 10
    $btn.Background      = if ($en) { [System.Windows.Media.BrushConverter]::new().ConvertFromString('#7B1A1A') } else { [System.Windows.Media.BrushConverter]::new().ConvertFromString('#1A5E2A') }
    $btn.Foreground      = [System.Windows.Media.Brushes]::White
    $btn.BorderThickness = [System.Windows.Thickness]::new(0)
    $btn.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
    $btn.Margin          = [System.Windows.Thickness]::new(8,0,0,0)
    [System.Windows.Controls.Grid]::SetColumn($btn, 1)

    if ($item.Source -ne 'Carpeta') {
        $ic = $item
        $btn.Add_Click({
            Set-StartupEnabled $ic.Source $ic.Name (-not $ic.Enabled) | Out-Null
            Refresh-StartupAuditUI
            SafeLog "Inicio actualizado`: $($ic.Name)"
        }.GetNewClosure())
    } else {
        $btn.IsEnabled = $false; $btn.Opacity = 0.35
    }

    $grid.Children.Add($sp)  | Out-Null
    $grid.Children.Add($btn) | Out-Null
    $border.Child = $grid
    return $border
}

function Refresh-StartupAuditUI() {
    $panel = Get-C 'startupAuditList'
    if (-not $panel) { return }
    $panel.Children.Clear()
    $all = Get-AllStartupItems
    foreach ($item in $all) {
        try { $panel.Children.Add((New-StartupAuditRow $item)) | Out-Null } catch {}
    }
    $info = Get-C 'lblStartupInfo'
    if ($info) { $info.Text = "$($all.Count) entradas de inicio encontradas" }
}

function Refresh-CleanerUI() {
    $panel = Get-C 'cleanerList'
    if (-not $panel) { return }
    $panel.Children.Clear()
    $script:cleanerCBs  = @{}
    $script:sizeLbls    = @{}

    foreach ($cat in $script:CleanCats) {
        $border = New-Object System.Windows.Controls.Border
        $border.Background   = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#0F0F22')
        $border.CornerRadius = [System.Windows.CornerRadius]::new(4)
        $border.Margin       = [System.Windows.Thickness]::new(0,0,0,4)
        $border.Padding      = [System.Windows.Thickness]::new(10,8,10,8)

        $grid = New-Object System.Windows.Controls.Grid
        $c0 = New-Object System.Windows.Controls.ColumnDefinition; $c0.Width = [System.Windows.GridLength]::Auto
        $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = [System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)
        $c2 = New-Object System.Windows.Controls.ColumnDefinition; $c2.Width = [System.Windows.GridLength]::Auto
        $grid.ColumnDefinitions.Add($c0); $grid.ColumnDefinitions.Add($c1); $grid.ColumnDefinitions.Add($c2)

        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.IsChecked  = $cat.Checked
        $cb.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $cb.Margin     = [System.Windows.Thickness]::new(0,0,10,0)
        $cb.Foreground = [System.Windows.Media.Brushes]::White
        if ($cat.Admin -and -not $script:IsAdmin) { $cb.IsEnabled = $false; $cb.Opacity = 0.4 }
        [System.Windows.Controls.Grid]::SetColumn($cb, 0)
        $script:cleanerCBs[$cat.Id] = $cb

        $sp = New-Object System.Windows.Controls.StackPanel
        $sp.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        [System.Windows.Controls.Grid]::SetColumn($sp, 1)

        $t1 = New-Object System.Windows.Controls.TextBlock
        $t1.Text       = $cat.Name
        $t1.FontWeight = [System.Windows.FontWeights]::SemiBold
        $t1.Foreground = if ($cat.Admin -and -not $script:IsAdmin) { [System.Windows.Media.BrushConverter]::new().ConvertFromString('#444455') } else { [System.Windows.Media.Brushes]::White }

        $t2 = New-Object System.Windows.Controls.TextBlock
        $t2.Text       = $cat.Desc
        $t2.FontSize   = 10
        $t2.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#888899')

        $sp.Children.Add($t1) | Out-Null
        $sp.Children.Add($t2) | Out-Null

        $szLbl = New-Object System.Windows.Controls.TextBlock
        $szLbl.Text       = '---'
        $szLbl.FontSize   = 11
        $szLbl.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#888899')
        $szLbl.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
        $szLbl.Margin     = [System.Windows.Thickness]::new(8,0,0,0)
        [System.Windows.Controls.Grid]::SetColumn($szLbl, 2)
        $script:sizeLbls[$cat.Id] = $szLbl

        $grid.Children.Add($cb)    | Out-Null
        $grid.Children.Add($sp)    | Out-Null
        $grid.Children.Add($szLbl) | Out-Null
        $border.Child = $grid
        $panel.Children.Add($border) | Out-Null
    }
}

function Invoke-Analyze() {
    $info = Get-C 'lblCleanerInfo'
    if ($info) { $info.Text = 'Calculando tamanos...' }
    $total = 0.0
    foreach ($cat in $script:CleanCats) {
        try {
            $mb = if ($cat.Id -eq 'Recycle') { Get-RecycleSizeMB } else { Get-FolderSizeMB $cat.Path }
            $lbl = $script:sizeLbls[$cat.Id]
            if ($lbl) { $lbl.Text = "${mb} MB" }
            $cb = $script:cleanerCBs[$cat.Id]
            if ($cb -and $cb.IsChecked) { $total += $mb }
        } catch {}
    }
    if ($info) { $info.Text = "Total seleccionado`: $([Math]::Round($total,1)) MB" }
}

function Invoke-Clean() {
    $freed = 0.0; $cnt = 0
    foreach ($cat in $script:CleanCats) {
        $cb = $script:cleanerCBs[$cat.Id]
        if (-not $cb -or -not $cb.IsChecked) { continue }
        if ($cat.Admin -and -not $script:IsAdmin) { continue }
        try {
            $before = if ($cat.Id -eq 'Recycle') { Get-RecycleSizeMB } else { Get-FolderSizeMB $cat.Path }
            switch ($cat.Id) {
                'Recycle'   { Clear-RecycleBin -Force -EA SilentlyContinue }
                'Thumbs'    { Get-ChildItem $cat.Path -Filter 'thumbcache_*.db' -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue }
                'Recent'    { Get-ChildItem $cat.Path -File -EA SilentlyContinue | Remove-Item -Force -EA SilentlyContinue }
                default     { if ($cat.Path -and (Test-Path $cat.Path)) { Get-ChildItem $cat.Path -Recurse -Force -EA SilentlyContinue | Remove-Item -Recurse -Force -EA SilentlyContinue } }
            }
            $after  = if ($cat.Id -eq 'Recycle') { Get-RecycleSizeMB } else { Get-FolderSizeMB $cat.Path }
            $freed += [Math]::Max(0, $before - $after)
            $cnt++
        } catch {}
    }
    $info = Get-C 'lblCleanerInfo'
    if ($info) { $info.Text = "$cnt categorias limpiadas - $([Math]::Round($freed,1)) MB liberados" }
    SafeLog "Limpieza completa`: $([Math]::Round($freed,1)) MB liberados"
    Invoke-Analyze
}

function Refresh-FirewallUI() {
    $panel = Get-C 'firewallList'
    if (-not $panel) { return }
    $panel.Children.Clear()
    $rules = @(Get-SSFWRules)

    if ($rules.Count -eq 0) {
        $lbl = New-Object System.Windows.Controls.TextBlock
        $lbl.Text        = "No hay reglas de bloqueo activas.`n`nUsa 'Bloquear nueva app' para impedir que una aplicacion acceda a Internet."
        $lbl.Foreground  = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#555566')
        $lbl.TextWrapping = [System.Windows.TextWrapping]::Wrap
        $lbl.Margin      = [System.Windows.Thickness]::new(10,20,10,0)
        $panel.Children.Add($lbl) | Out-Null
    } else {
        foreach ($rule in $rules) {
            $border = New-Object System.Windows.Controls.Border
            $border.Background   = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#0F0F22')
            $border.CornerRadius = [System.Windows.CornerRadius]::new(4)
            $border.Margin       = [System.Windows.Thickness]::new(0,0,0,4)
            $border.Padding      = [System.Windows.Thickness]::new(10,6,10,6)

            $grid = New-Object System.Windows.Controls.Grid
            $c0 = New-Object System.Windows.Controls.ColumnDefinition; $c0.Width = [System.Windows.GridLength]::new(1,[System.Windows.GridUnitType]::Star)
            $c1 = New-Object System.Windows.Controls.ColumnDefinition; $c1.Width = [System.Windows.GridLength]::Auto
            $grid.ColumnDefinitions.Add($c0); $grid.ColumnDefinitions.Add($c1)

            $sp = New-Object System.Windows.Controls.StackPanel
            $sp.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
            [System.Windows.Controls.Grid]::SetColumn($sp, 0)

            $t1 = New-Object System.Windows.Controls.TextBlock
            $t1.Text       = ($rule.DisplayName -replace '^SS Block: ','')
            $t1.FontWeight = [System.Windows.FontWeights]::SemiBold
            $t1.Foreground = [System.Windows.Media.Brushes]::White

            $t2 = New-Object System.Windows.Controls.TextBlock
            $t2.Text       = if ($rule.AppPath) { $rule.AppPath } else { '(ruta no disponible)' }
            $t2.FontSize   = 9
            $t2.FontFamily = New-Object System.Windows.Media.FontFamily('Consolas')
            $t2.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#444466')

            $sp.Children.Add($t1) | Out-Null
            $sp.Children.Add($t2) | Out-Null

            $badgeSp = New-Object System.Windows.Controls.StackPanel
            $badgeSp.Orientation = [System.Windows.Controls.Orientation]::Horizontal
            $badgeSp.VerticalAlignment = [System.Windows.VerticalAlignment]::Center
            [System.Windows.Controls.Grid]::SetColumn($badgeSp, 1)

            $badge = New-Object System.Windows.Controls.Border
            $badge.Background   = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#7B1A1A')
            $badge.CornerRadius = [System.Windows.CornerRadius]::new(3)
            $badge.Padding      = [System.Windows.Thickness]::new(6,2,6,2)
            $badge.Margin       = [System.Windows.Thickness]::new(0,0,6,0)
            $badgeTxt = New-Object System.Windows.Controls.TextBlock
            $badgeTxt.Text = 'BLOQUEADO'; $badgeTxt.FontSize = 9; $badgeTxt.Foreground = [System.Windows.Media.Brushes]::White
            $badge.Child = $badgeTxt

            $btn = New-Object System.Windows.Controls.Button
            $btn.Content         = 'Eliminar'
            $btn.Padding         = [System.Windows.Thickness]::new(8,3,8,3)
            $btn.FontSize        = 10
            $btn.Background      = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#2A2A3E')
            $btn.Foreground      = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#AAAACC')
            $btn.BorderThickness = [System.Windows.Thickness]::new(0)
            $btn.VerticalAlignment = [System.Windows.VerticalAlignment]::Center

            $rc = $rule
            $btn.Add_Click({
                Remove-SSFWBlock $rc.DisplayName | Out-Null
                Refresh-FirewallUI
                SafeLog "Regla eliminada`: $($rc.DisplayName)"
            }.GetNewClosure())

            $badgeSp.Children.Add($badge) | Out-Null
            $badgeSp.Children.Add($btn)   | Out-Null
            $grid.Children.Add($sp)       | Out-Null
            $grid.Children.Add($badgeSp)  | Out-Null
            $border.Child = $grid
            $panel.Children.Add($border)  | Out-Null
        }
    }
    $info = Get-C 'lblFirewallInfo'
    if ($info) { $info.Text = "$($rules.Count) aplicaciones bloqueadas por SecuritySuite" }
}

# ── XAML ──────────────────────────────────────────────────────────────────────
[xml]$xaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="SecuritySuite" Height="820" Width="450"
    Background="#0A0A1A" Foreground="#E0E0E0"
    WindowStartupLocation="CenterScreen" ResizeMode="CanMinimize"
    FontFamily="Segoe UI" FontSize="12">
  <Grid>
    <Grid.RowDefinitions>
      <RowDefinition Height="64"/>
      <RowDefinition Height="*"/>
      <RowDefinition Height="28"/>
    </Grid.RowDefinitions>

    <!-- Header -->
    <Border Grid.Row="0" Background="#12122A">
      <Grid Margin="14,0">
        <Grid.ColumnDefinitions>
          <ColumnDefinition Width="Auto"/>
          <ColumnDefinition Width="*"/>
          <ColumnDefinition Width="Auto"/>
        </Grid.ColumnDefinitions>
        <TextBlock Grid.Column="0" Text="&#x1F6E1;" FontSize="26" VerticalAlignment="Center" Margin="0,0,10,0"/>
        <StackPanel Grid.Column="1" VerticalAlignment="Center">
          <TextBlock Text="SecuritySuite" FontSize="18" FontWeight="Bold" Foreground="#FF4444"/>
          <TextBlock Text="Privacidad y seguridad para Windows 10 / 11" FontSize="10" Foreground="#666677"/>
        </StackPanel>
        <Border Grid.Column="2" Background="#1A1A2E" CornerRadius="8" Padding="14,4" VerticalAlignment="Center">
          <StackPanel HorizontalAlignment="Center">
            <TextBlock x:Name="lblScore" Text="--" FontSize="22" FontWeight="Bold" Foreground="#FF4444" HorizontalAlignment="Center"/>
            <ProgressBar x:Name="scoreBar" Minimum="0" Maximum="100" Value="0" Height="3" Margin="0,2,0,0" Background="#1A1A2E" Foreground="#FF4444" BorderThickness="0"/>
            <TextBlock Text="/ 100" FontSize="8" Foreground="#444455" HorizontalAlignment="Center"/>
          </StackPanel>
        </Border>
      </Grid>
    </Border>

    <!-- Tab Control -->
    <TabControl Grid.Row="1" Background="#0A0A1A" BorderThickness="0">
      <TabControl.Resources>
        <Style TargetType="TabItem">
          <Setter Property="Background" Value="#0F0F22"/>
          <Setter Property="Foreground" Value="#888899"/>
          <Setter Property="BorderThickness" Value="0"/>
          <Setter Property="Padding" Value="12,7"/>
          <Setter Property="FontSize" Value="11"/>
          <Setter Property="Template">
            <Setter.Value>
              <ControlTemplate TargetType="TabItem">
                <Border x:Name="bd" Background="{TemplateBinding Background}" Margin="1,0">
                  <ContentPresenter ContentSource="Header" HorizontalAlignment="Center" VerticalAlignment="Center" Margin="{TemplateBinding Padding}"/>
                </Border>
                <ControlTemplate.Triggers>
                  <Trigger Property="IsSelected" Value="True">
                    <Setter TargetName="bd" Property="Background" Value="#1E1E3A"/>
                    <Setter Property="Foreground" Value="#FF4444"/>
                  </Trigger>
                  <Trigger Property="IsMouseOver" Value="True">
                    <Setter TargetName="bd" Property="Background" Value="#181830"/>
                  </Trigger>
                </ControlTemplate.Triggers>
              </ControlTemplate>
            </Setter.Value>
          </Setter>
        </Style>
      </TabControl.Resources>

      <!-- Tab 1: Telemetria -->
      <TabItem Header="&#x1F4E1; Telemetria">
        <Grid Background="#0A0A1A" Margin="8,6,8,6">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#190808" CornerRadius="4" Padding="10,6" Margin="0,0,0,6" BorderBrush="#330000" BorderThickness="1">
            <TextBlock Text="Servicios y tareas programadas que recopilan y envian datos a Microsoft. Desactivarlos no afecta el funcionamiento normal del sistema." TextWrapping="Wrap" Foreground="#AA7777" FontSize="11"/>
          </Border>
          <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,6">
            <Button x:Name="btnDisableAllTel" Content="Desactivar todo" Background="#7B1A1A" Foreground="White" BorderThickness="0" Padding="10,5" Margin="0,0,6,0" FontSize="11" Cursor="Hand"/>
            <Button x:Name="btnEnableAllTel"  Content="Restaurar todo"  Background="#2A2A3E" Foreground="#AAAACC" BorderThickness="0" Padding="10,5" Margin="0,0,6,0" FontSize="11" Cursor="Hand"/>
            <Button x:Name="btnRefTel"        Content="Actualizar"      Background="#2A2A3E" Foreground="#AAAACC" BorderThickness="0" Padding="10,5"                   FontSize="11" Cursor="Hand"/>
          </StackPanel>
          <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
            <StackPanel x:Name="telemetryList"/>
          </ScrollViewer>
          <TextBlock Grid.Row="3" x:Name="lblTelemetryInfo" Text="" Foreground="#555566" FontSize="10" Margin="0,4,0,0"/>
        </Grid>
      </TabItem>

      <!-- Tab 2: Auditor de Inicio -->
      <TabItem Header="&#x1F680; Inicio">
        <Grid Background="#0A0A1A" Margin="8,6,8,6">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0A0A1A" CornerRadius="4" Padding="10,6" Margin="0,0,0,6" BorderBrush="#1E1E3A" BorderThickness="1">
            <TextBlock Text="Programas configurados para ejecutarse al iniciar Windows. Desactivar los 'No esenciales' puede mejorar el arranque significativamente." TextWrapping="Wrap" Foreground="#888899" FontSize="11"/>
          </Border>
          <Button Grid.Row="1" x:Name="btnRefStartup" Content="Actualizar lista" Background="#2A2A3E" Foreground="#AAAACC" BorderThickness="0" Padding="10,5" HorizontalAlignment="Left" Margin="0,0,0,6" FontSize="11" Cursor="Hand"/>
          <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
            <StackPanel x:Name="startupAuditList"/>
          </ScrollViewer>
          <TextBlock Grid.Row="3" x:Name="lblStartupInfo" Text="" Foreground="#555566" FontSize="10" Margin="0,4,0,0"/>
        </Grid>
      </TabItem>

      <!-- Tab 3: Limpiador de rastros -->
      <TabItem Header="&#x1F9F9; Rastros">
        <Grid Background="#0A0A1A" Margin="8,6,8,6">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0A0A1A" CornerRadius="4" Padding="10,6" Margin="0,0,0,6" BorderBrush="#1E1E3A" BorderThickness="1">
            <TextBlock Text="Elimina archivos temporales, cachés e historiales. Primero analiza los tamanos, luego limpia lo seleccionado." TextWrapping="Wrap" Foreground="#888899" FontSize="11"/>
          </Border>
          <ScrollViewer Grid.Row="1" VerticalScrollBarVisibility="Auto">
            <StackPanel x:Name="cleanerList"/>
          </ScrollViewer>
          <StackPanel Grid.Row="2" Orientation="Horizontal" Margin="0,6,0,4">
            <Button x:Name="btnAnalyze"   Content="Analizar tamanos" Background="#2A2A3E" Foreground="#AAAACC" BorderThickness="0" Padding="10,5" Margin="0,0,6,0" FontSize="11" Cursor="Hand"/>
            <Button x:Name="btnClean"     Content="Limpiar seleccion" Background="#7B1A1A" Foreground="White"   BorderThickness="0" Padding="10,5" Margin="0,0,6,0" FontSize="11" Cursor="Hand"/>
            <Button x:Name="btnSelAll"    Content="Seleccionar todo"  Background="#2A2A3E" Foreground="#AAAACC" BorderThickness="0" Padding="10,5"                   FontSize="11" Cursor="Hand"/>
          </StackPanel>
          <TextBlock Grid.Row="3" x:Name="lblCleanerInfo" Text="" Foreground="#555566" FontSize="10"/>
        </Grid>
      </TabItem>

      <!-- Tab 4: Firewall -->
      <TabItem Header="&#x1F525; Firewall">
        <Grid Background="#0A0A1A" Margin="8,6,8,6">
          <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
          </Grid.RowDefinitions>
          <Border Grid.Row="0" Background="#0A0A1A" CornerRadius="4" Padding="10,6" Margin="0,0,0,6" BorderBrush="#1E1E3A" BorderThickness="1">
            <TextBlock Text="Bloquea aplicaciones especificas del acceso a Internet. Util para apps que envian datos sin necesidad. Requiere administrador." TextWrapping="Wrap" Foreground="#888899" FontSize="11"/>
          </Border>
          <StackPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,6">
            <Button x:Name="btnBlockApp"  Content="Bloquear nueva app" Background="#7B1A1A" Foreground="White"   BorderThickness="0" Padding="10,5" Margin="0,0,6,0" FontSize="11" Cursor="Hand"/>
            <Button x:Name="btnRefFW"     Content="Actualizar"         Background="#2A2A3E" Foreground="#AAAACC" BorderThickness="0" Padding="10,5" Margin="0,0,6,0" FontSize="11" Cursor="Hand"/>
            <Button x:Name="btnFWAdvanced" Content="Firewall avanzado" Background="#2A2A3E" Foreground="#AAAACC" BorderThickness="0" Padding="10,5"                   FontSize="11" Cursor="Hand"/>
          </StackPanel>
          <ScrollViewer Grid.Row="2" VerticalScrollBarVisibility="Auto">
            <StackPanel x:Name="firewallList"/>
          </ScrollViewer>
          <TextBlock Grid.Row="3" x:Name="lblFirewallInfo" Text="" Foreground="#555566" FontSize="10" Margin="0,4,0,0"/>
        </Grid>
      </TabItem>

    </TabControl>

    <!-- Status Bar -->
    <StatusBar Grid.Row="2" Background="#080818" Foreground="#555566" FontSize="10">
      <StatusBarItem>
        <TextBlock x:Name="lblAdminStatus" Text=""/>
      </StatusBarItem>
      <Separator Background="#1E1E3A"/>
      <StatusBarItem HorizontalContentAlignment="Stretch">
        <TextBlock x:Name="lblStatus" Text="Listo"/>
      </StatusBarItem>
      <StatusBarItem HorizontalAlignment="Right">
        <TextBlock Text="SecuritySuite v1.0.1"/>
      </StatusBarItem>
    </StatusBar>
  </Grid>
</Window>
'@

# ── Cargar XAML ───────────────────────────────────────────────────────────────
try {
    $reader = [System.Xml.XmlNodeReader]::new($xaml)
    $script:window = [System.Windows.Markup.XamlReader]::Load($reader)
} catch {
    [System.Windows.MessageBox]::Show("Error al cargar interfaz: $_`n`nVerificar compatibilidad con .NET/WPF.", 'SecuritySuite', 'OK', 'Error')
    exit
}

# ── Conectar eventos ──────────────────────────────────────────────────────────
$btnDAT  = try { $script:window.FindName('btnDisableAllTel') } catch { $null }
$btnEAT  = try { $script:window.FindName('btnEnableAllTel')  } catch { $null }
$btnRT   = try { $script:window.FindName('btnRefTel')        } catch { $null }
$btnRS   = try { $script:window.FindName('btnRefStartup')    } catch { $null }
$btnAn   = try { $script:window.FindName('btnAnalyze')       } catch { $null }
$btnCl   = try { $script:window.FindName('btnClean')         } catch { $null }
$btnSA   = try { $script:window.FindName('btnSelAll')        } catch { $null }
$btnBA   = try { $script:window.FindName('btnBlockApp')      } catch { $null }
$btnRFW  = try { $script:window.FindName('btnRefFW')         } catch { $null }
$btnFWA  = try { $script:window.FindName('btnFWAdvanced')    } catch { $null }

On $btnDAT 'Click' {
    if (-not $script:IsAdmin) {
        [System.Windows.MessageBox]::Show('Requiere administrador para modificar servicios del sistema.`nEjecuta SecuritySuite como administrador.', 'SecuritySuite', 'OK', 'Warning') | Out-Null
        return
    }
    SafeLog 'Desactivando telemetria...'
    foreach ($s in $script:TelSvcs)  { Set-SvcDisabled  $s.Name | Out-Null }
    foreach ($t in $script:TelTasks) { Set-TaskDisabled $t.Path  | Out-Null }
    Refresh-TelemetryUI; Update-Score
    SafeLog "Telemetria desactivada ($($script:TelSvcs.Count + $script:TelTasks.Count) elementos)"
}

On $btnEAT 'Click' {
    foreach ($s in $script:TelSvcs)  { Set-SvcEnabled  $s.Name | Out-Null }
    foreach ($t in $script:TelTasks) { Set-TaskEnabled $t.Path  | Out-Null }
    Refresh-TelemetryUI; Update-Score
    SafeLog 'Telemetria restaurada a estado original'
}

On $btnRT  'Click' { Refresh-TelemetryUI; Update-Score; SafeLog 'Lista de telemetria actualizada' }
On $btnRS  'Click' { Refresh-StartupAuditUI; SafeLog 'Lista de inicio actualizada' }
On $btnAn  'Click' { Invoke-Analyze }

On $btnCl  'Click' {
    $r = [System.Windows.MessageBox]::Show('Limpiar los elementos seleccionados?`nEsta accion no se puede deshacer.', 'SecuritySuite', 'YesNo', 'Question')
    if ($r -eq 'Yes') { Invoke-Clean }
}

On $btnSA  'Click' {
    foreach ($id in $script:cleanerCBs.Keys) {
        $cb = $script:cleanerCBs[$id]
        if ($cb -and $cb.IsEnabled) { $cb.IsChecked = $true }
    }
}

On $btnBA  'Click' {
    if (-not $script:IsAdmin) {
        [System.Windows.MessageBox]::Show('Requiere administrador para crear reglas de Firewall.', 'SecuritySuite', 'OK', 'Warning') | Out-Null
        return
    }
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Title            = 'Selecciona la aplicacion a bloquear del acceso a Internet'
    $dlg.Filter           = 'Ejecutables (*.exe)|*.exe|Todos los archivos (*.*)|*.*'
    $dlg.InitialDirectory = 'C:\Program Files'
    if ($dlg.ShowDialog() -eq 'OK') {
        $exe  = $dlg.FileName
        $name = [IO.Path]::GetFileNameWithoutExtension($exe)
        $ok   = Add-SSFWBlock $exe $name
        if ($ok) { SafeLog "Bloqueado`: $name"; Refresh-FirewallUI }
        else      { SafeLog "Error al crear regla para`: $name" }
    }
}

On $btnRFW 'Click' { Refresh-FirewallUI; SafeLog 'Reglas de Firewall actualizadas' }
On $btnFWA 'Click' { try { Start-Process 'wf.msc' } catch {} }

# Admin status indicator
try {
    $lblA = $script:window.FindName('lblAdminStatus')
    if ($lblA) {
        $lblA.Text = if ($script:IsAdmin) { '● Administrador' } else { '● Usuario estandar — funciones limitadas' }
        $lblA.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($(if ($script:IsAdmin) { '#2ECC71' } else { '#F39C12' }))
    }
} catch {}

# Icono de ventana (desde icon.ico si existe)
try {
    $icoPath = Join-Path $script:AppDir 'icon.ico'
    if (Test-Path $icoPath) {
        $script:window.Icon = [System.Windows.Media.Imaging.BitmapImage]::new([Uri]::new($icoPath))
    }
} catch {}

# ── Inicializar UI ────────────────────────────────────────────────────────────
try { Refresh-TelemetryUI    } catch {}
try { Refresh-StartupAuditUI } catch {}
try { Refresh-CleanerUI      } catch {}
try { Refresh-FirewallUI     } catch {}
try { Update-Score           } catch {}

# ── Mostrar ventana ───────────────────────────────────────────────────────────
$script:window.ShowDialog() | Out-Null

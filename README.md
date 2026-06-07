# SecuritySuite

Suite de seguridad y privacidad para Windows 10 y Windows 11.
Desactiva la telemetría de Microsoft, gestiona el inicio de Windows, limpia rastros digitales y controla el Firewall — sin instalación, sin publicidad, sin enviar datos a nadie.

> Desarrollado por **Enmanuel Gil** — Código abierto, gratuito, auditable.

---

## Funciones

### 📡 Telemetría de Windows
- Lista los **7 servicios** y **9 tareas programadas** de Windows que recopilan y envían datos a Microsoft
- Muestra el estado actual de cada uno: activo o desactivado
- Clasificación por nivel de riesgo: **Alto / Medio / Bajo**
- **Desactivar todo** con un clic — no afecta el funcionamiento normal del sistema
- **Restaurar** si necesitas revertir los cambios

Servicios que controla: `DiagTrack`, `dmwappushsvc`, `WerSvc`, `XblAuthManager`, `XblGameSave`, `XboxNetApiSvc`, `MapsBroker`

Tareas que controla: `Compat Appraiser`, `CEIP Consolidator`, `Kernel CEIP`, `USB CEIP`, `Disk Diagnostic`, `WER Queue`, `Feedback Client` y más

### 🚀 Auditor de Inicio
- Lista **todos los programas** configurados para ejecutarse al iniciar Windows
- Fuentes: registro `HKCU`, registro `HKLM` y carpetas de inicio del sistema
- Clasificación inteligente por categoría:
  - `Sistema` — componente del SO, no modificar
  - `No esencial` — aplicaciones que ralentizan el arranque sin ser necesarias
  - `Revisar` — drivers y software de terceros
  - `Desconocido` — entrada no clasificada
- **Activar / Desactivar** cada entrada con un clic (vía clave `StartupApproved` del registro)

### 🧹 Limpiador de Rastros
- Selección granular por categoría con **vista previa del tamaño** antes de limpiar

| Categoría | Requiere admin |
|---|---|
| Temporales de usuario (`%TEMP%`) | No |
| Temporales del sistema (`C:\Windows\Temp`) | Sí |
| Caché de miniaturas del Explorador | No |
| Caché de Internet / Edge / WebView2 | No |
| Archivos recientes (MRU) | No |
| Prefetch | Sí |
| Caché de Windows Update (puede liberar GBs) | Sí |
| Papelera de reciclaje | No |

### 🔥 Gestor de Firewall
- Bloquea cualquier aplicación del acceso a Internet con un **selector de archivo**
- Lista todas las reglas de bloqueo creadas por SecuritySuite
- Elimina reglas individualmente
- Acceso directo al Firewall avanzado de Windows (`wf.msc`)

### Puntuación de seguridad (0–100)
- Calculada en tiempo real según el estado de la telemetría
- 🟢 Verde: 70–100 (bien configurado)
- 🟡 Amarillo: 40–69 (mejorable)
- 🔴 Rojo: 0–39 (telemetría activa)

---

## Instalación

### Opción A — Ejecutable (recomendado)

1. Descarga `SecuritySuite-v1.0.0.zip` desde [Releases](https://github.com/EnMaNueL-G/SecuritySuite/releases/latest)
2. Extrae en cualquier carpeta
3. Ejecuta `SecuritySuite.exe`

> Para funciones completas (modificar servicios del sistema, Firewall, limpieza de archivos del sistema): **ejecutar como administrador** → clic derecho → "Ejecutar como administrador"

> Windows puede mostrar SmartScreen la primera vez. Haz clic en **"Más información" → "Ejecutar de todas formas"**.

### Opción B — Script PowerShell

1. Descarga y extrae el ZIP
2. Ejecuta `SecuritySuite.bat` como administrador

---

## Requisitos

| Requisito | Versión |
|---|---|
| Sistema operativo | Windows 10 (v1903) o Windows 11 |
| PowerShell | 5.1 (incluido en Windows) |
| .NET Framework | 4.7.2 (incluido en Windows 10+) |
| Arquitectura | x64 |

---

## ¿Qué funciona sin administrador?

**Sin admin:** monitoreo de telemetría (solo lectura), auditor de inicio (HKCU), limpieza de temporales de usuario, caché de miniaturas, caché de Internet, MRU, papelera.

**Con admin:** modificar servicios del sistema, deshabilitar tareas programadas, limpiar `C:\Windows\Temp` y Prefetch, limpiar caché de Windows Update, crear/eliminar reglas de Firewall.

---

## Arquitectura técnica

```
SecuritySuite.ps1
├── Módulo Telemetría
│   ├── Get-SvcStartType / Set-SvcDisabled / Set-SvcEnabled
│   │     → Win32_Service (WMI) — Stop-Service + Set-Service
│   └── Get-TaskStatusStr / Set-TaskDisabled / Set-TaskEnabled
│         → Get-ScheduledTask / Disable-ScheduledTask / Enable-ScheduledTask
│
├── Módulo Auditor de Inicio
│   ├── HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
│   ├── HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
│   ├── Carpetas de inicio de usuario y sistema
│   └── StartupApproved: bytes [2,...] = activo, [3,...] = inactivo
│
├── Módulo Limpiador de Rastros
│   ├── Get-FolderSizeMB — calcula tamaño con recursion + medida
│   ├── Selección granular con checkbox por categoría
│   └── Limpieza diferenciada por tipo (thumbcache, Recent, Clear-RecycleBin...)
│
├── Módulo Firewall
│   ├── Get-NetFirewallRule → reglas con prefijo "SS Block:"
│   ├── New-NetFirewallRule (fallback: netsh advfirewall)
│   └── Remove-NetFirewallRule (fallback: netsh)
│
└── Motor de puntuación
      Peso por riesgo: Alto=4pts, Medio=2pts, Bajo=1pt
      Score = (puntos obtenidos / máximo posible) × 100
```

**Decisiones técnicas:**
- Sin `Add-Type -TypeDefinition` — arranque en 0ms sin compilación C#
- UI dinámica 100% en código PowerShell — compatible con PS2EXE
- Todos los bloques de UI en `try/catch` independientes — ningún error genera popup
- `Get-C()` + `On()` — acceso null-safe a controles WPF
- Closures con `.GetNewClosure()` para captura correcta de variables en handlers

---

## Compilar desde fuente

```powershell
git clone https://github.com/EnMaNueL-G/SecuritySuite.git
cd SecuritySuite
powershell -ExecutionPolicy Bypass -File _build.ps1
```

`_build.ps1` instala [PS2EXE](https://github.com/MScholtes/PS2EXE) automáticamente si no está disponible, genera el icono y compila el EXE.

---

## Estructura del repositorio

```
SecuritySuite/
├── SecuritySuite.ps1     # Script principal (~700 lineas)
├── SecuritySuite.bat     # Launcher con elevacion UAC automatica
├── SecuritySuite.exe     # Ejecutable compilado (ver Releases)
├── icon.ico              # Icono generado programaticamente
├── _build.ps1            # Script de compilacion (PS2EXE)
└── README.md             # Este archivo
```

---

## Diferencias con otras herramientas

| Función | SecuritySuite | O&O ShutUp10 | Spybot Anti-Beacon | CCleaner |
|---|---|---|---|---|
| Telemetría Windows | ✅ Servicios + Tareas | ✅ | ✅ | ❌ |
| Auditor de inicio con riesgo | ✅ | ❌ | ❌ | Básico |
| Limpiador de rastros | ✅ Con preview | ❌ | ❌ | ✅ Con ads |
| Gestor de Firewall | ✅ | ❌ | ❌ | ❌ |
| Puntuación de seguridad | ✅ | ❌ | ❌ | ❌ |
| Sin instalación | ✅ | ✅ | ❌ | ❌ |
| Sin publicidad | ✅ | ✅ | ✅ | ❌ |
| Sin telemetría propia | ✅ | ✅ | ✅ | ❌ |
| Código abierto | ✅ | ❌ | ❌ | ❌ |
| Precio | Gratis | Gratis | Gratis | Freemium |

---

## Changelog

### v1.0.0
- Lanzamiento inicial
- Módulo de telemetría: 7 servicios + 9 tareas programadas
- Auditor de inicio con clasificación automática de riesgo
- Limpiador de rastros: 8 categorías con análisis de tamaño previo
- Gestor de Firewall: bloquear/desbloquear apps del acceso a Internet
- Puntuación de seguridad 0-100 en tiempo real
- Indicador de modo administrador en barra de estado

---

## Donaciones

Si SecuritySuite te ha sido útil:

- **Binance Pay ID:** `1140153333`
- **BSC BEP20:** `0x0a9a0d8d816ede885d1d4a5c94369a72ef86b3c1`

---

## Licencia

MIT License — libre para usar, modificar y distribuir.

© 2026 Enmanuel Gil — [github.com/EnMaNueL-G](https://github.com/EnMaNueL-G)

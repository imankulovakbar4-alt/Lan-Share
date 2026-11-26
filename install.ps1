# ============ НАСТРОЙКИ ============
$ProcessName    = "Photoshop"   # имя процесса без .exe ("Photoshop", "chrome", ...)
$HideWindow     = $true         # скрыть окно с экрана и панели задач
$OptimizeMemory = $true         # выгрузить working set из ОЗУ

# Код состояния ShowWindow:
#   0 = скрыть полностью (SW_HIDE)
#   6 = свернуть (SW_MINIMIZE)
#   7 = свернуть без активации
$WindowState    = 0
# ===================================

# ---------- КУДА СТАВИМ СЕБЯ ----------
$StartupFolder = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
$FilePath      = "$PSScriptRoot\file.txt"   # файл, который перемещаем в автозагрузку
$SelfPath      = $PSCommandPath
$ManagedBySelf = $false
$RunningFromStartup = $false

if ($SelfPath) {
    $SelfName    = Split-Path $SelfPath -Leaf
    $StartupCopy = Join-Path $StartupFolder $SelfName
    $RunningFromStartup = ($SelfPath -ieq $StartupCopy)
    $ManagedBySelf = $true
}

# ---------- УСТАНОВКА В АВТОЗАГРУЗКУ (только при ручном запуске) ----------
if ($ManagedBySelf -and -not $RunningFromStartup) {
    if (Test-Path -LiteralPath $FilePath) {
        try {
            Move-Item -LiteralPath $FilePath -Destination $StartupFolder -Force
            Write-Host "Перемещён в автозагрузку: $(Join-Path $StartupFolder (Split-Path $FilePath -Leaf))" -ForegroundColor Cyan
        } catch {
            Write-Host "Не удалось переместить в Startup: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Файл для установки не найден: $FilePath" -ForegroundColor Yellow
    }
}

# ============ ОСНОВНАЯ РАБОТА ============
$code = @"
using System;
using System.Runtime.InteropServices;

public class MemoryOptimizer {
    [DllImport("psapi.dll")]
    public static extern bool EmptyWorkingSet(IntPtr hwProc);

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
"@

if (-not ([System.Management.Automation.PSTypeName]'MemoryOptimizer').Type) {
    Add-Type -TypeDefinition $code
}

$procs = @(Get-Process -Name $ProcessName -ErrorAction SilentlyContinue)

if ($procs.Count -eq 0) {
    Write-Host "Процесс '$ProcessName' не найден." -ForegroundColor Yellow
} else {
    Write-Host "Найдено процессов '$ProcessName': $($procs.Count)" -ForegroundColor Cyan

    foreach ($p in $procs) {
        Write-Host "`n→ PID $($p.Id)  ($($p.ProcessName))" -ForegroundColor Green

        if ($HideWindow) {
            if ($p.MainWindowHandle -ne 0) {
                $ok = [MemoryOptimizer]::ShowWindow($p.MainWindowHandle, $WindowState)
                if ($ok) {
                    Write-Host "   окно: применён режим $WindowState" -ForegroundColor Gray
                } else {
                    Write-Host "   окно: ShowWindow вернул false" -ForegroundColor DarkYellow
                }
            } else {
                Write-Host "   окно: нет главного окна (уже скрыто или процесс без GUI)" -ForegroundColor DarkGray
            }
        }

        if ($OptimizeMemory) {
            try {
                $memBefore = $p.WorkingSet64 / 1MB
                $ok = [MemoryOptimizer]::EmptyWorkingSet($p.Handle)
                Start-Sleep -Milliseconds 200
                $p.Refresh()
                $memAfter = $p.WorkingSet64 / 1MB
                if ($ok) {
                    Write-Host ("   память: {0:N1} МБ → {1:N1} МБ" -f $memBefore, $memAfter) -ForegroundColor Gray
                } else {
                    Write-Host "   память: EmptyWorkingSet вернул false (нет прав?)" -ForegroundColor DarkYellow
                }
            } catch {
                Write-Host "   память: ошибка — $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    }
}

# ============ SELF-DELETE (только при ручном запуске) ============
# Если запущенный файл ($SelfPath) и перемещаемый ($FilePath) — это один и тот же файл,
# то после Move-Item его по старому пути уже нет, и самоудаление не нужно.
# Если это разные файлы — удаляем сам скрипт-лаунчер.
if ($ManagedBySelf -and -not $RunningFromStartup -and
    (Test-Path -LiteralPath $SelfPath) -and
    ($SelfPath -ine $FilePath)) {
    Write-Host "`nУдаляю исходный файл: $SelfPath" -ForegroundColor DarkGray
    Start-Process -WindowStyle Hidden -FilePath "cmd.exe" `
        -ArgumentList "/c timeout /t 2 /nobreak >nul & del /f /q `"$SelfPath`""
}

Write-Host "`nГотово." -ForegroundColor Cyan
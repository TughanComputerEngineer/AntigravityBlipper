$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$jarPath = Join-Path $repoRoot "desktopApp\build\libs\blipper-desktop-1.0.0.jar"
$csPath = Join-Path $PSScriptRoot "BlipperLauncher.cs"
$icoPath = Join-Path $PSScriptRoot "blipper.ico"
$exeOutPath = Join-Path $repoRoot "AntigravityBlipper.exe"
$cscPath = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

if (-not (Test-Path $jarPath)) {
    $env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
    $env:GRADLE_USER_HOME = Join-Path $repoRoot ".gradle-home"
    & (Join-Path $repoRoot "desktopApp\gradlew.bat") -p (Join-Path $repoRoot "desktopApp") bootJar
}

# Generate a crisp 256x256 PNG-backed Windows .ico icon (cyber dark shield + neon cyan lightning bolt)
Add-Type -AssemblyName System.Drawing
$bmp = New-Object System.Drawing.Bitmap(256, 256, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.Clear([System.Drawing.Color]::Transparent)

$bgBrush = New-Object System.Drawing.Drawing2D.LinearGradientBrush(
    (New-Object System.Drawing.Rectangle(16, 16, 224, 224)),
    [System.Drawing.Color]::FromArgb(255, 11, 22, 38),
    [System.Drawing.Color]::FromArgb(255, 6, 78, 59),
    45.0
)
$borderPen = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(255, 16, 185, 129), 10)

$path = New-Object System.Drawing.Drawing2D.GraphicsPath
$radius = 52
$rect = New-Object System.Drawing.Rectangle(18, 18, 220, 220)
$path.AddArc($rect.X, $rect.Y, $radius, $radius, 180, 90)
$path.AddArc($rect.Right - $radius, $rect.Y, $radius, $radius, 270, 90)
$path.AddArc($rect.Right - $radius, $rect.Bottom - $radius, $radius, $radius, 0, 90)
$path.AddArc($rect.X, $rect.Bottom - $radius, $radius, $radius, 90, 90)
$path.CloseFigure()

$g.FillPath($bgBrush, $path)
$g.DrawPath($borderPen, $path)

$boltPoints = [System.Drawing.PointF[]]@(
    (New-Object System.Drawing.PointF(146, 42)),
    (New-Object System.Drawing.PointF(74, 138)),
    (New-Object System.Drawing.PointF(126, 138)),
    (New-Object System.Drawing.PointF(108, 214)),
    (New-Object System.Drawing.PointF(184, 116)),
    (New-Object System.Drawing.PointF(132, 116))
)
$boltBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(255, 56, 189, 248))
$g.FillPolygon($boltBrush, $boltPoints)

$pngMs = New-Object System.IO.MemoryStream
$bmp.Save($pngMs, [System.Drawing.Imaging.ImageFormat]::Png)
$pngBytes = $pngMs.ToArray()

$icoFs = [System.IO.File]::Open($icoPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
$bw = New-Object System.IO.BinaryWriter($icoFs)
# ICONDIR header (0, type=1 icon, count=1)
$bw.Write([UInt16]0)
$bw.Write([UInt16]1)
$bw.Write([UInt16]1)
# ICONDIRENTRY (width=0->256, height=0->256, colors=0, reserved=0, planes=1, bpp=32, size, offset=22)
$bw.Write([Byte]0)
$bw.Write([Byte]0)
$bw.Write([Byte]0)
$bw.Write([Byte]0)
$bw.Write([UInt16]1)
$bw.Write([UInt16]32)
$bw.Write([UInt32]$pngBytes.Length)
$bw.Write([UInt32]22)
$bw.Write($pngBytes)
$bw.Flush()
$icoFs.Close()
$g.Dispose()
$bmp.Dispose()

& $cscPath `
    /nologo `
    /optimize+ `
    /target:winexe `
    /platform:x64 `
    "/win32icon:$icoPath" `
    "/out:$exeOutPath" `
    "/resource:$jarPath,blipper.jar" `
    /r:System.dll `
    /r:System.Drawing.dll `
    /r:System.Windows.Forms.dll `
    $csPath

if ($LASTEXITCODE -ne 0) {
    throw "csc.exe failed with exit code $LASTEXITCODE"
}

Write-Output "EXE_CREATED=$exeOutPath"

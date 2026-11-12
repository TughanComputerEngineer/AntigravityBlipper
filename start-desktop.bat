@echo off
setlocal EnableExtensions

set "ROOT_DIR=%~dp0"
set "JAR_PATH=%ROOT_DIR%desktopApp\build\libs\blipper-desktop-1.0.0.jar"
set "STUDIO_JBR=C:\Program Files\Android\Android Studio\jbr"

if exist "%STUDIO_JBR%\bin\javaw.exe" (
    set "JAVA_HOME=%STUDIO_JBR%"
    set "JAVAW_EXE=%STUDIO_JBR%\bin\javaw.exe"
) else if defined JAVA_HOME if exist "%JAVA_HOME%\bin\javaw.exe" (
    set "JAVAW_EXE=%JAVA_HOME%\bin\javaw.exe"
) else (
    set "JAVAW_EXE=javaw.exe"
)

if not exist "%JAR_PATH%" (
    echo [AntigravityBlipper] Masaustu JAR derleniyor...
    call "%ROOT_DIR%desktopApp\gradlew.bat" -p "%ROOT_DIR%desktopApp" bootJar
    if errorlevel 1 (
        echo [HATA] Masaustu uygulamasi derlenemedi!
        pause
        exit /b 1
    )
)

start "" "%JAVAW_EXE%" -jar "%JAR_PATH%"
exit /b 0

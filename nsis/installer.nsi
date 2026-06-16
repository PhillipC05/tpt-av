; TPT-AV Windows Installer (NSIS)
; Build: makensis nsis/installer.nsi
; Requires: NSIS 3.x  https://nsis.sourceforge.io/
; Requires pre-built binaries in bin/windows/

!define PRODUCT_NAME "TPT-AV"
!define PRODUCT_VERSION "1.0.0"
!define INSTALL_DIR "$PROGRAMFILES64\TPT-AV"
!define CONFIG_DIR "$APPDATA\..\Local\ProgramData\TPT"

Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "..\bin\TPT-AV-Setup.exe"
InstallDir "${INSTALL_DIR}"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

; Pages
Page directory
Page instfiles
UninstPage uninstConfirm
UninstPage instfiles

Section "Core Files" SEC_CORE
  SetOutPath "$INSTDIR"

  ; Binaries
  File "..\bin\windows\tpt-guard.exe"
  File "..\bin\windows\tpt-patrol.exe"
  File "..\bin\windows\tpt-backup.exe"
  File "..\bin\windows\tptctl.exe"
  File "..\bin\windows\tpt-tray.exe"

  ; Web dashboard
  SetOutPath "$INSTDIR\web"
  File /r "..\web\static\*.*"

  ; Default config files (only if not present)
  SetOutPath "$APPDATA\..\ProgramData\TPT"
  IfFileExists "$APPDATA\..\ProgramData\TPT\guard.toml" +2
    File /oname=guard.toml "..\config\guard.toml.example"
  IfFileExists "$APPDATA\..\ProgramData\TPT\patrol.toml" +2
    File /oname=patrol.toml "..\config\patrol.toml.example"
  IfFileExists "$APPDATA\..\ProgramData\TPT\backup.toml" +2
    File /oname=backup.toml "..\config\backup.toml.example"

  ; Add to PATH
  EnVar::SetHKLM
  EnVar::AddValue "PATH" "$INSTDIR"

  ; Register Windows services
  nsExec::ExecToLog '"$INSTDIR\tpt-guard.exe"  --service-install'
  nsExec::ExecToLog '"$INSTDIR\tpt-patrol.exe" --service-install'

  ; Start services
  nsExec::ExecToLog 'net start tpt-guard'
  nsExec::ExecToLog 'net start tpt-patrol'

  ; Start Menu shortcut (opens dashboard URL)
  CreateDirectory "$SMPROGRAMS\TPT-AV"
  WriteIniStr "$SMPROGRAMS\TPT-AV\TPT-AV Dashboard.url" "InternetShortcut" "URL" "http://127.0.0.1:7731"
  CreateShortcut "$SMPROGRAMS\TPT-AV\TPT-AV Tray.lnk" "$INSTDIR\tpt-tray.exe"

  ; Write uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; Add to Programs & Features
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TPT-AV" \
    "DisplayName" "${PRODUCT_NAME} ${PRODUCT_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TPT-AV" \
    "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TPT-AV" \
    "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TPT-AV" \
    "Publisher" "TPT-AV Project"
SectionEnd

Section "Optional: TPT Backup" SEC_BACKUP
  nsExec::ExecToLog '"$INSTDIR\tpt-backup.exe" --service-install'
SectionEnd

Section "Uninstall"
  ; Stop and remove services
  nsExec::ExecToLog 'net stop  tpt-guard'
  nsExec::ExecToLog 'net stop  tpt-patrol'
  nsExec::ExecToLog 'net stop  tpt-backup'
  nsExec::ExecToLog '"$INSTDIR\tpt-guard.exe"  --service-remove'
  nsExec::ExecToLog '"$INSTDIR\tpt-patrol.exe" --service-remove'
  nsExec::ExecToLog '"$INSTDIR\tpt-backup.exe" --service-remove'

  ; Remove PATH entry
  EnVar::SetHKLM
  EnVar::DeleteValue "PATH" "$INSTDIR"

  ; Remove files
  RMDir /r "$INSTDIR"

  ; Remove Start Menu shortcuts
  RMDir /r "$SMPROGRAMS\TPT-AV"

  ; Remove registry
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\TPT-AV"
SectionEnd

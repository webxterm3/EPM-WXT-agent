; VSay Agent Windows Installer
; NSIS Modern User Interface Script

!include "MUI2.nsh"
!include "FileFunc.nsh"

; --------------------------------
; General Configuration
; --------------------------------

!define PRODUCT_NAME "wxt-agent"
!define PRODUCT_PUBLISHER "VSay"
!define PRODUCT_WEB_SITE "https://vsay.in"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\wxt-agent.exe"
; The key name is fixed rather than derived from PRODUCT_NAME, and it is the
; SAME key the agent's own `configure` writes. Two spellings meant two entries
; in Programs and Features for one product, on any machine where the installer
; ran and the agent was then enrolled.
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\EPMAgent"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; Version is passed during build
!ifndef VERSION
  !define VERSION "1.0.0"
!endif

!ifndef ARCH
  !define ARCH "amd64"
!endif

Name "${PRODUCT_NAME} ${VERSION}"
OutFile "wxt-agent-${VERSION}-windows-${ARCH}-setup.exe"
InstallDir "$PROGRAMFILES64\VSay\Agent"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
RequestExecutionLevel admin
ShowInstDetails show
ShowUnInstDetails show

; --------------------------------
; MUI Settings
; --------------------------------

!define MUI_ABORTWARNING

; Welcome page
!insertmacro MUI_PAGE_WELCOME

; License page (optional)
; !insertmacro MUI_PAGE_LICENSE "..\..\LICENSE"

; Directory page
!insertmacro MUI_PAGE_DIRECTORY

; Installation page
!insertmacro MUI_PAGE_INSTFILES

; Finish page
!define MUI_FINISHPAGE_RUN "$INSTDIR\wxt-agent.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "version"
!define MUI_FINISHPAGE_RUN_TEXT "Show version information"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

; Language
!insertmacro MUI_LANGUAGE "English"

; --------------------------------
; Installer Sections
; --------------------------------

Section "Main Application" SecMain
  SectionIn RO

  ; Set output path to installation directory
  SetOutPath "$INSTDIR"
  SetOverwrite on

  ; Copy main executable
  File "..\..\dist\bin\windows-${ARCH}\wxt-agent.exe"
  ; The session helper must land in the SAME directory as the agent: that is
  ; where the agent looks for it when starting a remote-control session.
  File "..\..\dist\bin\windows-${ARCH}\wxt-agent-session.exe"

  ; Create config directory
  CreateDirectory "$APPDATA\VSay"

  ; Create start menu shortcuts
  CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\VSay Agent.lnk" "$INSTDIR\wxt-agent.exe"
  CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"

  ; Add to PATH
  EnVar::AddValue "PATH" "$INSTDIR"

  ; Write registry keys
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\wxt-agent.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayName" "$(^Name)"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayIcon" "$INSTDIR\wxt-agent.exe"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "URLInfoAbout" "${PRODUCT_WEB_SITE}"
  WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "Publisher" "${PRODUCT_PUBLISHER}"
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "NoModify" 1
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "NoRepair" 1

  ; Get and write install size
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" "EstimatedSize" "$0"

  ; Create uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

; --------------------------------
; Uninstaller Section
; --------------------------------

Section "Uninstall"
  ; Stop the agent FIRST.
  ;
  ; This was missing, and its absence is not cosmetic: the agent runs from a
  ; scheduled task registered as SYSTEM at boot. Deleting the files without
  ; removing the task leaves Windows trying to launch a binary that is no
  ; longer there, every single startup, forever — and leaves a running agent
  ; holding the files being deleted.
  DetailPrint "Stopping the agent service..."
  nsExec::ExecToLog 'schtasks /end /tn "VsayAgent"'
  Pop $0
  nsExec::ExecToLog 'schtasks /delete /tn "VsayAgent" /f'
  Pop $0
  ; Belt and braces: a task that was ended may still have a live process.
  nsExec::ExecToLog 'taskkill /f /im wxt-agent.exe'
  Pop $0
  nsExec::ExecToLog 'taskkill /f /im wxt-agent-session.exe'
  Pop $0

  ; Remove from PATH
  EnVar::DeleteValue "PATH" "$INSTDIR"

  ; Delete files
  Delete "$INSTDIR\wxt-agent.exe"
  Delete "$INSTDIR\wxt-agent-session.exe"
  Delete "$INSTDIR\uninstall.exe"

  ; Delete shortcuts
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\VSay Agent.lnk"
  Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
  RMDir "$SMPROGRAMS\${PRODUCT_NAME}"

  ; Delete installation directory
  RMDir "$INSTDIR"
  RMDir "$PROGRAMFILES64\VSay"

  ; Delete registry keys
  DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"

  ; Optionally remove config.
  ;
  ; The path is C:\ProgramData\vsay, which is where configure actually writes
  ; (agent.yaml, certs\, logs\). The old $APPDATA\VSay was simply the wrong
  ; directory: answering "Yes" deleted nothing and left the enrolment
  ; certificates on the machine.
  MessageBox MB_YESNO "Also remove the agent's configuration, certificates and logs?$\r$\n$\r$\n(C:\ProgramData\vsay)$\r$\n$\r$\nKeep them if you are reinstalling and want this machine to stay enrolled." IDNO skip_config
    RMDir /r "C:\ProgramData\vsay"
  skip_config:

  ; The machine stays listed in the portal until an administrator removes it
  ; there. Said out loud, because an uninstaller that goes quiet leaves people
  ; assuming the whole thing is gone.
  MessageBox MB_OK "wxt-agent has been removed from this computer.$\r$\n$\r$\nNo user account was changed — this agent never created one.$\r$\n$\r$\nThe machine stays listed in the EPM portal until an administrator deletes it there."

  SetAutoClose true
SectionEnd

; --------------------------------
; Section Descriptions
; --------------------------------

!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "Install VSay Agent application and add to system PATH."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

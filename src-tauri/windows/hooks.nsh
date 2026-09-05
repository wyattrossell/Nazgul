; Nazgul NSIS hooks. Tauri includes this file into the generated installer.
; Always place a shortcut on the desktop, whether the install is interactive, passive or silent.

!macro NSIS_HOOK_POSTINSTALL
  CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "" "$INSTDIR\${MAINBINARYNAME}.exe" 0
!macroend

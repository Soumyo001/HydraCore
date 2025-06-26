Dim answer, userInput, voice
Set voice = CreateObject("SAPI.SpVoice")


voice.Speak "Initializing neural scan"
MsgBox "Subject: " & CreateObject("WScript.Network").UserName, vbCritical, "CORTICAL PROTOCOL"
WScript.Sleep 2000

voice.Speak "Warning: Cognitive deterioration detected"
MsgBox "Your thoughts aren't your own anymore", vbExclamation, "SYNAPSE DEGRADATION"
WScript.Sleep 1500

voice.Speak "Tissue separation in progress"
MsgBox "Can you feel the fissures spreading through your gray matter?", vbQuestion, "NEURAL FRAGMENTATION"
WScript.Sleep 3000

answer = "silence"
userInput = InputBox( _
    "I sever connections yet create no wound." & vbCrLf & _
    "I scatter thoughts without touch or sound." & vbCrLf & _
    "I live in the space between synapses bright," & vbCrLf & _
    "And swallow memories whole in the night." & vbCrLf & vbCrLf & _
    "What surgical blade cuts without steel?" & vbCrLf & _
    "(Answer in one word)", _
    "CEREBRAL DISSECTION", _
    "Your answer..." _
)

Select Case LCase(Trim(userInput))
    Case answer
        voice.Speak "Cognitive reassembly initiated"
        MsgBox "The fragmentation ceases... for now", vbInformation, "TEMPORARY SANITY"
        
    Case ""
        voice.Speak "Void response detected"
        MsgBox "The emptiness consumes what remains", vbCritical, "NEURAL VACUUM"
        
    Case Else
        voice.Speak "Incorrect solution. Applying consequences"
        MsgBox "The fissures deepen..." & vbCrLf & _
               "You can feel the pieces drifting apart", _
               vbCritical, "COGNITIVE COLLAPSE"
End Select


voice.Speak "Remember: The blade never sleeps"
MsgBox "The dissection continues in your dreams", vbExclamation, "POST-SCRIPTUM"

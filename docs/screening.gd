Storage 
{
	{ Format 1.31 }
	{ GeneratedFrom TGD-version-2.01 }
	{ WrittenBy mmuehlen }
	{ WrittenOn "Mon May  6 14:03:22 2002" }
}

Document 
{
	{ Type "Generic Diagram" }
	{ Name screening.gd }
	{ Author root }
	{ CreatedOn "Mon Feb 18 11:14:02 2002" }
	{ Annotation "" }
}

Page 
{
	{ PageOrientation Portrait }
	{ PageSize A4 }
	{ ShowHeaders False }
	{ ShowFooters False }
	{ ShowNumbers False }
}

Scale 
{
	{ ScaleValue 0.569469 }
}

# GRAPH NODES

GenericNode 1
{
	{ Name "from CPE" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 2
{
	{ Name "CgPNs included\r(possibly contains network\rand user provided CgPN)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 3
{
	{ Name "CgPN\rincluded\r(only one CgPN possible:\ruser provided)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 16
{
	{ Name "convert CgPN to\rinternational format\r(prepend CC from profile)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 17
{
	{ Name "insert mainTelephoneNumber\r from CallTable" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 18
{
	{ Name "SI := \"network provided\"" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 19
{
	{ Name "get CLIR from CallTable" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 34
{
	{ Name "no CLIR: PI := \"restricted\rCLIR=TRUE: PI := \"restricted\"\rCLIR=FALSE: PI := \"allowed\"" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 35
{
	{ Name "CgPN ToN := international\rCgPN NPI := ISDN" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 36
{
	{ Name "match CgPN right-justified against\rtelephonenumber prefixes in CallTable\r(dots match any cipher;\r all dots must be matched)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 37
{
	{ Name "CgPN does match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 39
{
	{ Name "SI := \"User provided, verified\rand passed\"" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 40
{
	{ Name "get CLIR from CallTable" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 41
{
	{ Name "no CLIR: leave PI unchanged\rCLIR=TRUE: PI := \"restricted\"\rCLIR=FALSE: PI := \"allowed\"" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 70
{
	{ Name "get CdPN\r from CallTable" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 71
{
	{ Name "store CgPN for CDR generation\r(in international format)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 112
{
	{ Name "CdPN ToN := international\rCdPN NPI := ISDN" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 120
{
	{ Name "END" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 121
{
	{ Name "START" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 72
{
	{ Name "to CPE" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 73
{
	{ Name "remove CgPNs with PI = \"restricted\"" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 74
{
	{ Name "remove CgPNs with SI =\r\"User provided, not screened\" or\r\"User provided, verified and failed\"" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 144
{
	{ Name "TON = national ?" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 164
{
	{ Name "Number conversions" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 187
{
	{ Name "prepend inac to CgPN\rCgPN ToN := unknown" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 166
{
	{ Name "national call\r(CgPN and CdPN have\rthe same code from the\rcountry code table)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 167
{
	{ Name "convert CgPNs to national\rCgPN ToˆN := national" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 168
{
	{ Name "convert CdPNs to national\rCdPN ToN := national" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 200
{
	{ Name "voIPPrependCallbackAC" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 201
{
	{ Name "national call\r(CgPN and CdPN have\rthe same code from the\rcountry code table)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 202
{
	{ Name "prepend nac to CgPN\rCgPN ToN := unknown" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

# GRAPH EDGES

GenericEdge 5
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 1 }
	{ Subject2 3 }
}

GenericEdge 20
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 2 }
	{ Subject2 144 }
}

GenericEdge 22
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 3 }
	{ Subject2 17 }
}

GenericEdge 23
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 17 }
	{ Subject2 18 }
}

GenericEdge 24
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 18 }
	{ Subject2 19 }
}

GenericEdge 42
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 19 }
	{ Subject2 34 }
}

GenericEdge 43
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 34 }
	{ Subject2 35 }
}

GenericEdge 45
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 3 }
	{ Subject2 36 }
}

GenericEdge 46
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 37 }
	{ Subject2 17 }
}

GenericEdge 47
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 36 }
	{ Subject2 37 }
}

GenericEdge 48
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 37 }
	{ Subject2 39 }
}

GenericEdge 50
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 39 }
	{ Subject2 40 }
}

GenericEdge 51
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 40 }
	{ Subject2 41 }
}

GenericEdge 79
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 41 }
	{ Subject2 35 }
}

GenericEdge 80
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 35 }
	{ Subject2 70 }
}

GenericEdge 81
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 35 }
	{ Subject2 71 }
}

GenericEdge 125
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 121 }
	{ Subject2 1 }
}

GenericEdge 134
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 1 }
	{ Subject2 2 }
}

GenericEdge 136
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 2 }
	{ Subject2 70 }
}

GenericEdge 82
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 70 }
	{ Subject2 112 }
}

GenericEdge 83
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 73 }
	{ Subject2 74 }
}

GenericEdge 84
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 72 }
	{ Subject2 73 }
}

GenericEdge 151
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 72 }
	{ Subject2 120 }
}

GenericEdge 152
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 74 }
	{ Subject2 151 }
}

GenericEdge 153
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 144 }
	{ Subject2 16 }
}

GenericEdge 154
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 16 }
	{ Subject2 35 }
}

GenericEdge 155
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 144 }
	{ Subject2 154 }
}

GenericEdge 170
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 166 }
	{ Subject2 167 }
}

GenericEdge 171
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 167 }
	{ Subject2 168 }
}

GenericEdge 203
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 112 }
	{ Subject2 166 }
}

GenericEdge 204
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 166 }
	{ Subject2 200 }
}

GenericEdge 205
{
	{ Name "TRUE" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 200 }
	{ Subject2 201 }
}

GenericEdge 206
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 201 }
	{ Subject2 187 }
}

GenericEdge 207
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 201 }
	{ Subject2 202 }
}

GenericEdge 208
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 168 }
	{ Subject2 204 }
}

GenericEdge 209
{
	{ Name "FALSE    " }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 200 }
	{ Subject2 72 }
}

GenericEdge 210
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 187 }
	{ Subject2 209 }
}

GenericEdge 211
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 202 }
	{ Subject2 209 }
}

# VIEWS AND GRAPHICAL SHAPES

View 6
{
	{ Index "0" }
	{ Parent 0 }
}

Diamond 7
{
	{ View 6 }
	{ Subject 1 }
	{ Position 370 220 }
	{ Size 114 66 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 8
{
	{ View 6 }
	{ Subject 2 }
	{ Position 240 320 }
	{ Size 178 126 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 9
{
	{ View 6 }
	{ Subject 3 }
	{ Position 510 320 }
	{ Size 187 126 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 11
{
	{ View 6 }
	{ Subject 5 }
	{ FromShape 7 }
	{ ToShape 9 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 427 220 }
	{ Point 510 220 }
	{ Point 510 257 }
	{ NamePosition 468 210 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 25
{
	{ View 6 }
	{ Subject 20 }
	{ FromShape 8 }
	{ ToShape 146 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 240 383 }
	{ Point 240 640 }
	{ NamePosition 226 511 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 26
{
	{ View 6 }
	{ Subject 16 }
	{ Position 240 750 }
	{ Size 126 50 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 28
{
	{ View 6 }
	{ Subject 17 }
	{ Position 510 450 }
	{ Size 162 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 29
{
	{ View 6 }
	{ Subject 18 }
	{ Position 510 520 }
	{ Size 160 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 30
{
	{ View 6 }
	{ Subject 19 }
	{ Position 510 590 }
	{ Size 166 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 31
{
	{ View 6 }
	{ Subject 22 }
	{ FromShape 9 }
	{ ToShape 28 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 383 }
	{ Point 510 431 }
	{ NamePosition 496 407 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 32
{
	{ View 6 }
	{ Subject 23 }
	{ FromShape 28 }
	{ ToShape 29 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 469 }
	{ Point 510 501 }
	{ NamePosition 496 485 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 33
{
	{ View 6 }
	{ Subject 24 }
	{ FromShape 29 }
	{ ToShape 30 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 539 }
	{ Point 510 571 }
	{ NamePosition 496 555 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 52
{
	{ View 6 }
	{ Subject 34 }
	{ Position 510 670 }
	{ Size 172 64 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 53
{
	{ View 6 }
	{ Subject 42 }
	{ FromShape 30 }
	{ ToShape 52 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 609 }
	{ Point 510 638 }
	{ NamePosition 496 623 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 54
{
	{ View 6 }
	{ Subject 35 }
	{ Position 510 750 }
	{ Size 176 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 55
{
	{ View 6 }
	{ Subject 43 }
	{ FromShape 52 }
	{ ToShape 54 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 702 }
	{ Point 510 731 }
	{ NamePosition 496 716 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 57
{
	{ View 6 }
	{ Subject 36 }
	{ Position 770 320 }
	{ Size 185 56 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 58
{
	{ View 6 }
	{ Subject 45 }
	{ FromShape 9 }
	{ ToShape 57 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 603 320 }
	{ Point 678 320 }
	{ NamePosition 640 310 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 59
{
	{ View 6 }
	{ Subject 37 }
	{ Position 770 450 }
	{ Size 106 70 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 60
{
	{ View 6 }
	{ Subject 46 }
	{ FromShape 59 }
	{ ToShape 28 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 717 450 }
	{ Point 591 450 }
	{ NamePosition 654 440 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 61
{
	{ View 6 }
	{ Subject 47 }
	{ FromShape 57 }
	{ ToShape 59 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 770 348 }
	{ Point 770 415 }
	{ NamePosition 756 381 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 63
{
	{ View 6 }
	{ Subject 48 }
	{ FromShape 59 }
	{ ToShape 64 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 823 450 }
	{ Point 980 450 }
	{ Point 980 501 }
	{ NamePosition 901 440 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 64
{
	{ View 6 }
	{ Subject 39 }
	{ Position 980 520 }
	{ Size 190 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 65
{
	{ View 6 }
	{ Subject 40 }
	{ Position 980 590 }
	{ Size 188 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 66
{
	{ View 6 }
	{ Subject 41 }
	{ Position 980 670 }
	{ Size 190 60 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 68
{
	{ View 6 }
	{ Subject 50 }
	{ FromShape 64 }
	{ ToShape 65 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 980 539 }
	{ Point 980 571 }
	{ NamePosition 966 555 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 69
{
	{ View 6 }
	{ Subject 51 }
	{ FromShape 65 }
	{ ToShape 66 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 980 609 }
	{ Point 980 640 }
	{ NamePosition 966 624 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 91
{
	{ View 6 }
	{ Subject 79 }
	{ FromShape 66 }
	{ ToShape 54 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 984 700 }
	{ Point 984 753 }
	{ Point 598 753 }
	{ NamePosition 970 726 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 92
{
	{ View 6 }
	{ Subject 70 }
	{ Position 510 830 }
	{ Size 176 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 93
{
	{ View 6 }
	{ Subject 80 }
	{ FromShape 54 }
	{ ToShape 92 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 769 }
	{ Point 510 811 }
	{ NamePosition 496 790 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 94
{
	{ View 6 }
	{ Subject 71 }
	{ Position 780 830 }
	{ Size 174 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 95
{
	{ View 6 }
	{ Subject 81 }
	{ FromShape 54 }
	{ ToShape 94 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 595 769 }
	{ Point 695 811 }
	{ NamePosition 650 781 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Dashed }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 116
{
	{ View 6 }
	{ Subject 112 }
	{ Position 510 910 }
	{ Size 180 44 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 127
{
	{ View 6 }
	{ Subject 120 }
	{ Position 510 1620 }
	{ Size 106 66 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 128
{
	{ View 6 }
	{ Subject 121 }
	{ Position 370 130 }
	{ Size 110 58 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 131
{
	{ View 6 }
	{ Subject 125 }
	{ FromShape 128 }
	{ ToShape 7 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 370 159 }
	{ Point 370 187 }
	{ NamePosition 356 173 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 135
{
	{ View 6 }
	{ Subject 134 }
	{ FromShape 7 }
	{ ToShape 8 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 313 220 }
	{ Point 240 220 }
	{ Point 240 257 }
	{ NamePosition 276 210 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 140
{
	{ View 6 }
	{ Subject 136 }
	{ FromShape 8 }
	{ ToShape 92 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 4 }
	{ Point 151 319 }
	{ Point 103 319 }
	{ Point 103 826 }
	{ Point 422 826 }
	{ NamePosition 89 572 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 96
{
	{ View 6 }
	{ Subject 72 }
	{ Position 510 1500 }
	{ Size 104 72 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 97
{
	{ View 6 }
	{ Subject 82 }
	{ FromShape 92 }
	{ ToShape 116 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 849 }
	{ Point 510 888 }
	{ NamePosition 496 868 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 98
{
	{ View 6 }
	{ Subject 73 }
	{ Position 740 1500 }
	{ Size 192 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 99
{
	{ View 6 }
	{ Subject 74 }
	{ Position 740 1570 }
	{ Size 186 42 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 101
{
	{ View 6 }
	{ Subject 83 }
	{ FromShape 98 }
	{ ToShape 99 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 740 1519 }
	{ Point 740 1549 }
	{ NamePosition 726 1534 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 102
{
	{ View 6 }
	{ Subject 84 }
	{ FromShape 96 }
	{ ToShape 98 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 562 1500 }
	{ Point 644 1500 }
	{ NamePosition 603 1490 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 146
{
	{ View 6 }
	{ Subject 144 }
	{ Position 240 670 }
	{ Size 110 60 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 159
{
	{ View 6 }
	{ Subject 151 }
	{ FromShape 96 }
	{ ToShape 127 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 1536 }
	{ Point 510 1587 }
	{ NamePosition 496 1561 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 160
{
	{ View 6 }
	{ Subject 152 }
	{ FromShape 99 }
	{ ToShape 159 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 647 1570 }
	{ Point 510 1570 }
	{ NamePosition 578 1560 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 161
{
	{ View 6 }
	{ Subject 153 }
	{ FromShape 146 }
	{ ToShape 26 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 240 700 }
	{ Point 240 725 }
	{ NamePosition 226 712 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 162
{
	{ View 6 }
	{ Subject 154 }
	{ FromShape 26 }
	{ ToShape 54 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 303 750 }
	{ Point 422 750 }
	{ NamePosition 362 740 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 163
{
	{ View 6 }
	{ Subject 155 }
	{ FromShape 146 }
	{ ToShape 162 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 295 670 }
	{ Point 360 670 }
	{ Point 360 750 }
	{ NamePosition 327 660 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 165
{
	{ View 6 }
	{ Subject 164 }
	{ Position 370 60 }
	{ Size 242 33 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-bold-r-normal--24*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 194
{
	{ View 6 }
	{ Subject 187 }
	{ Position 770 1330 }
	{ Size 192 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 175
{
	{ View 6 }
	{ Subject 166 }
	{ Position 510 1050 }
	{ Size 172 114 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 177
{
	{ View 6 }
	{ Subject 167 }
	{ Position 770 1050 }
	{ Size 186 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 178
{
	{ View 6 }
	{ Subject 170 }
	{ FromShape 175 }
	{ ToShape 177 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 596 1050 }
	{ Point 677 1050 }
	{ NamePosition 636 1040 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 179
{
	{ View 6 }
	{ Subject 168 }
	{ Position 770 1120 }
	{ Size 186 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 180
{
	{ View 6 }
	{ Subject 171 }
	{ FromShape 177 }
	{ ToShape 179 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 770 1069 }
	{ Point 770 1101 }
	{ NamePosition 756 1085 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 212
{
	{ View 6 }
	{ Subject 203 }
	{ FromShape 116 }
	{ ToShape 175 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 932 }
	{ Point 510 993 }
	{ NamePosition 496 962 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 213
{
	{ View 6 }
	{ Subject 200 }
	{ Position 510 1220 }
	{ Size 172 114 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 214
{
	{ View 6 }
	{ Subject 204 }
	{ FromShape 175 }
	{ ToShape 213 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 1107 }
	{ Point 510 1163 }
	{ NamePosition 496 1135 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 215
{
	{ View 6 }
	{ Subject 201 }
	{ Position 770 1220 }
	{ Size 172 114 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 216
{
	{ View 6 }
	{ Subject 205 }
	{ FromShape 213 }
	{ ToShape 215 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 596 1220 }
	{ Point 684 1220 }
	{ NamePosition 640 1210 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 217
{
	{ View 6 }
	{ Subject 202 }
	{ Position 1000 1220 }
	{ Size 192 38 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 218
{
	{ View 6 }
	{ Subject 206 }
	{ FromShape 215 }
	{ ToShape 194 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 770 1277 }
	{ Point 770 1311 }
	{ NamePosition 756 1294 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 219
{
	{ View 6 }
	{ Subject 207 }
	{ FromShape 215 }
	{ ToShape 217 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 856 1220 }
	{ Point 904 1220 }
	{ NamePosition 880 1210 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 220
{
	{ View 6 }
	{ Subject 208 }
	{ FromShape 179 }
	{ ToShape 214 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 677 1120 }
	{ Point 510 1120 }
	{ NamePosition 593 1110 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 221
{
	{ View 6 }
	{ Subject 209 }
	{ FromShape 213 }
	{ ToShape 96 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 1277 }
	{ Point 510 1464 }
	{ NamePosition 496 1370 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 222
{
	{ View 6 }
	{ Subject 210 }
	{ FromShape 194 }
	{ ToShape 221 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 770 1349 }
	{ Point 770 1380 }
	{ Point 510 1380 }
	{ NamePosition 756 1364 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 223
{
	{ View 6 }
	{ Subject 211 }
	{ FromShape 217 }
	{ ToShape 221 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 1000 1239 }
	{ Point 1000 1420 }
	{ Point 510 1420 }
	{ NamePosition 986 1329 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}


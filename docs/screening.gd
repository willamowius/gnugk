Storage 
{
	{ Format 1.31 }
	{ GeneratedFrom TGD-version-2.01 }
	{ WrittenBy storm }
	{ WrittenOn "Mon Apr 29 13:35:19 2002" }
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

GenericNode 14
{
	{ Name "Select a CgPN to set\r(first possible from list):\r\r1. User provided,verified\rand passed\r\r2. Network provided\r\r3. User provided, not\rscreened\r\r4. User provided, verified\rand failed" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 16
{
	{ Name "convert CgPN to\rinternational format\r(prepend CC from .ini)" }
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

GenericNode 38
{
	{ Name "insert complete telephoneNumber\rfrom CallTable" }
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
	{ Subject2 14 }
}

GenericEdge 21
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 14 }
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
	{ Subject2 38 }
}

GenericEdge 49
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 38 }
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
	{ Position 370 200 }
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
	{ Position 240 300 }
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
	{ Position 510 300 }
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
	{ Point 424 201 }
	{ Point 511 203 }
	{ Point 510 237 }
	{ NamePosition 467 193 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 15
{
	{ View 6 }
	{ Subject 14 }
	{ Position 240 500 }
	{ Size 126 184 }
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

Line 25
{
	{ View 6 }
	{ Subject 20 }
	{ FromShape 8 }
	{ ToShape 15 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 240 363 }
	{ Point 240 408 }
	{ NamePosition 226 385 }
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
	{ Position 240 730 }
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

Line 27
{
	{ View 6 }
	{ Subject 21 }
	{ FromShape 15 }
	{ ToShape 146 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 240 592 }
	{ Point 240 620 }
	{ NamePosition 226 606 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
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
	{ Position 510 430 }
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
	{ Position 510 500 }
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
	{ Position 510 570 }
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
	{ Point 510 363 }
	{ Point 510 411 }
	{ NamePosition 496 387 }
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
	{ Point 510 449 }
	{ Point 510 481 }
	{ NamePosition 496 465 }
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
	{ Point 510 519 }
	{ Point 510 551 }
	{ NamePosition 496 535 }
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
	{ Position 510 650 }
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
	{ Point 510 589 }
	{ Point 510 618 }
	{ NamePosition 496 603 }
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
	{ Position 510 730 }
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
	{ Point 510 682 }
	{ Point 510 711 }
	{ NamePosition 496 696 }
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
	{ Position 770 300 }
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
	{ Point 603 300 }
	{ Point 678 300 }
	{ NamePosition 640 290 }
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
	{ Position 770 430 }
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
	{ Point 717 430 }
	{ Point 591 430 }
	{ NamePosition 654 420 }
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
	{ Point 770 328 }
	{ Point 770 395 }
	{ NamePosition 756 361 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 62
{
	{ View 6 }
	{ Subject 38 }
	{ Position 980 430 }
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

Line 63
{
	{ View 6 }
	{ Subject 48 }
	{ FromShape 59 }
	{ ToShape 62 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 823 430 }
	{ Point 887 430 }
	{ NamePosition 855 420 }
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
	{ Position 980 500 }
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
	{ Position 980 570 }
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
	{ Position 980 650 }
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

Line 67
{
	{ View 6 }
	{ Subject 49 }
	{ FromShape 62 }
	{ ToShape 64 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 980 449 }
	{ Point 980 481 }
	{ NamePosition 966 465 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
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
	{ Point 980 519 }
	{ Point 980 551 }
	{ NamePosition 966 535 }
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
	{ Point 980 589 }
	{ Point 980 620 }
	{ NamePosition 966 604 }
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
	{ Point 984 680 }
	{ Point 984 733 }
	{ Point 598 733 }
	{ NamePosition 970 706 }
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
	{ Position 510 810 }
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
	{ Point 510 749 }
	{ Point 510 791 }
	{ NamePosition 496 770 }
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
	{ Position 780 810 }
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
	{ Point 595 749 }
	{ Point 695 791 }
	{ NamePosition 650 761 }
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
	{ Position 510 890 }
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
	{ Position 370 110 }
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
	{ Point 370 139 }
	{ Point 370 167 }
	{ NamePosition 356 153 }
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
	{ Point 315 201 }
	{ Point 241 203 }
	{ Point 240 237 }
	{ NamePosition 278 193 }
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
	{ Point 151 299 }
	{ Point 103 299 }
	{ Point 103 806 }
	{ Point 422 806 }
	{ NamePosition 89 552 }
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
	{ Position 510 1480 }
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
	{ Point 510 829 }
	{ Point 510 868 }
	{ NamePosition 496 848 }
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
	{ Position 740 1480 }
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
	{ Position 740 1550 }
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
	{ Point 740 1499 }
	{ Point 740 1529 }
	{ NamePosition 726 1514 }
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
	{ Point 562 1480 }
	{ Point 644 1480 }
	{ NamePosition 603 1470 }
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
	{ Position 240 650 }
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
	{ Point 510 1516 }
	{ Point 510 1587 }
	{ NamePosition 496 1551 }
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
	{ Point 647 1550 }
	{ Point 510 1550 }
	{ NamePosition 578 1540 }
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
	{ Point 240 680 }
	{ Point 240 705 }
	{ NamePosition 226 692 }
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
	{ Point 303 730 }
	{ Point 422 730 }
	{ NamePosition 362 720 }
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
	{ Point 295 650 }
	{ Point 360 650 }
	{ Point 360 730 }
	{ NamePosition 327 640 }
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
	{ Position 370 40 }
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
	{ Position 770 1310 }
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
	{ Position 510 1030 }
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
	{ Position 770 1030 }
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
	{ Point 596 1030 }
	{ Point 677 1030 }
	{ NamePosition 636 1020 }
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
	{ Position 770 1100 }
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
	{ Point 770 1049 }
	{ Point 770 1081 }
	{ NamePosition 756 1065 }
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
	{ Point 510 912 }
	{ Point 510 973 }
	{ NamePosition 496 942 }
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
	{ Position 510 1200 }
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
	{ Point 510 1087 }
	{ Point 510 1143 }
	{ NamePosition 496 1115 }
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
	{ Position 770 1200 }
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
	{ Point 596 1200 }
	{ Point 684 1200 }
	{ NamePosition 640 1190 }
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
	{ Position 1000 1200 }
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
	{ Point 770 1257 }
	{ Point 770 1291 }
	{ NamePosition 756 1274 }
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
	{ Point 856 1200 }
	{ Point 904 1200 }
	{ NamePosition 880 1190 }
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
	{ Point 677 1100 }
	{ Point 510 1100 }
	{ NamePosition 593 1090 }
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
	{ Point 510 1257 }
	{ Point 510 1444 }
	{ NamePosition 496 1350 }
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
	{ Point 770 1329 }
	{ Point 770 1360 }
	{ Point 510 1360 }
	{ NamePosition 756 1344 }
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
	{ Point 1000 1219 }
	{ Point 1000 1400 }
	{ Point 510 1400 }
	{ NamePosition 986 1309 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}


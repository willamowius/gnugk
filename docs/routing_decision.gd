Storage 
{
	{ Format 1.31 }
	{ GeneratedFrom TGD-version-2.01 }
	{ WrittenBy storm }
	{ WrittenOn "Mon Nov 11 09:40:56 2002" }
}

Document 
{
	{ Type "Generic Diagram" }
	{ Name routing_decision.gd }
	{ Author nilsb }
	{ CreatedOn "Tue Jan 15 13:55:59 2002" }
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
	{ ScaleValue 0.859975 }
}

# GRAPH NODES

GenericNode 1
{
	{ Name "search in\rregistration table\r(CdPN is prefix of\rthe number or gw prefix in \rregistration table)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 2
{
	{ Name "full match\r(CdPN is eqal\rto number or gw prefix\rin registration table)\r" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 3
{
	{ Name "ARJ\rincompleteAddress" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 4
{
	{ Name "ACF" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 6
{
	{ Name "ARJ\rincompleteAddress" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 7
{
	{ Name "ARJ calledPartyNotRegistered\rOR\rACF and route call to VoiceMail" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 10
{
	{ Name "ACF" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 11
{
	{ Name "ARJ\rincompleteAddress" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 44
{
	{ Name "This shall never happen!\rIf we fail in here, all\rtrunk gateways are broken." }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 46
{
	{ Name "Routing complete but not\rnecessarily unique" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 47
{
	{ Name "Routing is unique" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 50
{
	{ Name "Routing Decision (I)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 52
{
	{ Name "ARJ\rcalledPartyNotRegistered" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 54
{
	{ Name "ARJ\runreachableDestination" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 55
{
	{ Name "Prefix of:\r+49532 is a prefix of +49532801520\rEqual:\r+49532 is not equal to +49532801520\r+49542801520 is (only) equal to +49542801520" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 74
{
	{ Name "for a CdPN 495246801867, we know that 495246 is countryCode + AreaCode and 801867 is subscriber number + extension\r LDAP search filter is (|(telephonenumber=4952461867*)(telephonenumber=49524680186.*)(telephonenumber=4952468018..*)\r(telephonenumber=495246801...*)(telephonenumber=49524680....*)(telephonenumber=4952468.....*))" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 80
{
	{ Name "If we fail here, the CdPN is neither\ra subscriber of ours nor do we\rhave a route to this destination" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 82
{
	{ Name "Routing Decision (II)\r(see special diagram)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 104
{
	{ Name "will choose one out\rof a list of possible routes\r(honors metrics, carrier codes)\rNOT YET IMPLEMENTED" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 105
{
	{ Name "might be a call to a non-registered\rsubscriber of ours, but we\rneed more ciphers to decide" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 106
{
	{ Name "call is meant for a terminal\rsubscriber of ours that is\rcurrently not registered" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 110
{
	{ Name "might be a call to a registered\rendpoint of ours, but we\rneed more ciphers to decide" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 111
{
	{ Name "might be a call to one of\rseveral potentially matching\rregistered endpoints, but we\rneed more ciphers to decide" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 114
{
	{ Name "profile for CdPN \rexists" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 115
{
	{ Name "search in registration \rtable for gateway with longest\r match  (the RegTable entry\ris prefix of CdPN)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 116
{
	{ Name "search for match against\rtelephoneNumber attribute\rin existing databases \r(CdPN is prefix of a number in a database entry\rOR\ra number in a database entry is  prefix of CdPN \rOR\rboth numbers are equal)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 128
{
	{ Name "START" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

# GRAPH EDGES

GenericEdge 12
{
	{ Name "=1" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 1 }
	{ Subject2 2 }
}

GenericEdge 13
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 2 }
	{ Subject2 3 }
}

GenericEdge 14
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 2 }
	{ Subject2 4 }
}

GenericEdge 16
{
	{ Name ">1" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 1 }
	{ Subject2 6 }
}

GenericEdge 17
{
	{ Name "CdPN is equal \rto database entry's \rtelephoneNumber" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 116 }
	{ Subject2 7 }
}

GenericEdge 21
{
	{ Name "CdPN is prefix of\rdatabase entry's \rtelephoneNumber" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 116 }
	{ Subject2 11 }
}

GenericEdge 57
{
	{ Name "no match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 115 }
	{ Subject2 52 }
}

GenericEdge 84
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 10 }
	{ Subject2 82 }
}

GenericEdge 86
{
	{ Name "no match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 116 }
	{ Subject2 54 }
}

GenericEdge 96
{
	{ Name "found at least \r1 router" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 115 }
	{ Subject2 10 }
}

GenericEdge 117
{
	{ Name "=0" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 1 }
	{ Subject2 114 }
}

GenericEdge 118
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 114 }
	{ Subject2 115 }
}

GenericEdge 124
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 114 }
	{ Subject2 116 }
}

GenericEdge 125
{
	{ Name "gateway found" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 116 }
	{ Subject2 115 }
}

GenericEdge 129
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 128 }
	{ Subject2 1 }
}

# VIEWS AND GRAPHICAL SHAPES

View 22
{
	{ Index "0" }
	{ Parent 0 }
}

Diamond 23
{
	{ View 22 }
	{ Subject 1 }
	{ Position 320 190 }
	{ Size 164 158 }
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

Diamond 24
{
	{ View 22 }
	{ Subject 2 }
	{ Position 510 190 }
	{ Size 142 108 }
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
	{ View 22 }
	{ Subject 12 }
	{ FromShape 23 }
	{ ToShape 24 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 402 190 }
	{ Point 439 190 }
	{ NamePosition 420 180 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 26
{
	{ View 22 }
	{ Subject 3 }
	{ Position 670 190 }
	{ Size 120 40 }
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
	{ View 22 }
	{ Subject 13 }
	{ FromShape 24 }
	{ ToShape 26 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 581 190 }
	{ Point 610 190 }
	{ NamePosition 595 180 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

RoundedBox 28
{
	{ View 22 }
	{ Subject 4 }
	{ Position 510 290 }
	{ Size 76 38 }
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

Line 29
{
	{ View 22 }
	{ Subject 14 }
	{ FromShape 24 }
	{ ToShape 28 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 244 }
	{ Point 510 271 }
	{ NamePosition 496 257 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 32
{
	{ View 22 }
	{ Subject 6 }
	{ Position 80 190 }
	{ Size 106 38 }
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

Line 33
{
	{ View 22 }
	{ Subject 16 }
	{ FromShape 23 }
	{ ToShape 32 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 238 190 }
	{ Point 133 190 }
	{ NamePosition 185 180 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 34
{
	{ View 22 }
	{ Subject 7 }
	{ Position 590 680 }
	{ Size 178 42 }
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

Line 35
{
	{ View 22 }
	{ Subject 17 }
	{ FromShape 123 }
	{ ToShape 34 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 519 532 }
	{ Point 580 659 }
	{ NamePosition 516 624 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

RoundedBox 40
{
	{ View 22 }
	{ Subject 10 }
	{ Position 280 760 }
	{ Size 110 38 }
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

EllipsedBox 42
{
	{ View 22 }
	{ Subject 11 }
	{ Position 400 650 }
	{ Size 106 38 }
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

Line 43
{
	{ View 22 }
	{ Subject 21 }
	{ FromShape 123 }
	{ ToShape 42 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 459 531 }
	{ Point 409 631 }
	{ NamePosition 386 574 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 45
{
	{ View 22 }
	{ Subject 44 }
	{ Position 80 730 }
	{ Size 127 37 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 48
{
	{ View 22 }
	{ Subject 46 }
	{ Position 400 760 }
	{ Size 120 26 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 49
{
	{ View 22 }
	{ Subject 47 }
	{ Position 520 320 }
	{ Size 84 20 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 51
{
	{ View 22 }
	{ Subject 50 }
	{ Position 340 30 }
	{ Size 232 32 }
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

EllipsedBox 59
{
	{ View 22 }
	{ Subject 52 }
	{ Position 80 680 }
	{ Size 136 46 }
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

Line 62
{
	{ View 22 }
	{ Subject 57 }
	{ FromShape 121 }
	{ ToShape 59 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 65 572 }
	{ Point 51 573 }
	{ Point 51 657 }
	{ NamePosition 76 614 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 63
{
	{ View 22 }
	{ Subject 54 }
	{ Position 670 550 }
	{ Size 136 46 }
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

TextBox 65
{
	{ View 22 }
	{ Subject 55 }
	{ Position 150 970 }
	{ Size 230 69 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 79
{
	{ View 22 }
	{ Subject 74 }
	{ Position 320 1040 }
	{ Size 601 37 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 81
{
	{ View 22 }
	{ Subject 80 }
	{ Position 670 600 }
	{ Size 160 37 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 88
{
	{ View 22 }
	{ Subject 82 }
	{ Position 280 840 }
	{ Size 132 38 }
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

Line 89
{
	{ View 22 }
	{ Subject 84 }
	{ FromShape 40 }
	{ ToShape 88 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 280 779 }
	{ Point 280 821 }
	{ NamePosition 266 800 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 92
{
	{ View 22 }
	{ Subject 86 }
	{ FromShape 123 }
	{ ToShape 63 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 665 470 }
	{ Point 690 470 }
	{ Point 690 527 }
	{ NamePosition 677 460 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 99
{
	{ View 22 }
	{ Subject 96 }
	{ FromShape 121 }
	{ ToShape 40 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 254 572 }
	{ Point 281 573 }
	{ Point 281 741 }
	{ NamePosition 243 644 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 107
{
	{ View 22 }
	{ Subject 104 }
	{ Position 420 840 }
	{ Size 141 48 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 108
{
	{ View 22 }
	{ Subject 105 }
	{ Position 390 690 }
	{ Size 162 37 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 109
{
	{ View 22 }
	{ Subject 106 }
	{ Position 590 730 }
	{ Size 125 37 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 112
{
	{ View 22 }
	{ Subject 110 }
	{ Position 660 240 }
	{ Size 140 37 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 113
{
	{ View 22 }
	{ Subject 111 }
	{ Position 90 240 }
	{ Size 136 48 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Invisible }
	{ FillStyle Unfilled }
	{ FillColor "white" }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 119
{
	{ View 22 }
	{ Subject 114 }
	{ Position 320 350 }
	{ Size 120 56 }
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

Line 120
{
	{ View 22 }
	{ Subject 117 }
	{ FromShape 23 }
	{ ToShape 119 }
	{ Curved False }
	{ End1 Empty }
	{ End2 Empty }
	{ Points 2 }
	{ Point 320 269 }
	{ Point 320 322 }
	{ NamePosition 306 295 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 121
{
	{ View 22 }
	{ Subject 115 }
	{ Position 160 570 }
	{ Size 198 112 }
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

Line 122
{
	{ View 22 }
	{ Subject 118 }
	{ FromShape 119 }
	{ ToShape 121 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 260 350 }
	{ Point 160 350 }
	{ Point 160 514 }
	{ NamePosition 210 340 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 123
{
	{ View 22 }
	{ Subject 116 }
	{ Position 490 470 }
	{ Size 350 150 }
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

Line 126
{
	{ View 22 }
	{ Subject 124 }
	{ FromShape 119 }
	{ ToShape 123 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 380 350 }
	{ Point 490 350 }
	{ Point 490 395 }
	{ NamePosition 435 340 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 127
{
	{ View 22 }
	{ Subject 125 }
	{ FromShape 123 }
	{ ToShape 121 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 315 470 }
	{ Point 170 470 }
	{ Point 160 514 }
	{ NamePosition 242 460 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

RoundedBox 130
{
	{ View 22 }
	{ Subject 128 }
	{ Position 320 70 }
	{ Size 110 38 }
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
	{ View 22 }
	{ Subject 129 }
	{ FromShape 130 }
	{ ToShape 23 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 320 89 }
	{ Point 320 111 }
	{ NamePosition 306 100 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}


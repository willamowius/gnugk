Storage 
{
	{ Format 1.31 }
	{ GeneratedFrom TGD-version-2.01 }
	{ WrittenBy storm }
	{ WrittenOn "Thu Mar 21 16:48:50 2002" }
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
	{ ScaleValue 1 }
}

# GRAPH NODES

GenericNode 1
{
	{ Name "search in\rregistration table\r(CdPN is prefix of\rthe number in \rregistration table)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 2
{
	{ Name "full match\r(CdPN is eqal\rto number in\rregistration table)\r" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 3
{
	{ Name "ARJ\rincomplete Address" }
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

GenericNode 5
{
	{ Name "LDAP Search for possibly\rmatching CPE entries against \rtelephonenumber attribute  in LDAP\rAfter search, \".\" are stripped from LDAP\r entries. If more than 1 LDAP\rentry is found, comparison is done\r against the one with the\rlongest prefix." }
	{ Annotation "blabla\r" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 6
{
	{ Name "ARJ\rincomplete Address" }
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

GenericNode 8
{
	{ Name "search in Registration table\rfor trunk gateway with longest\rmatch (i.e. the RegTable entry\ris prefix of CdPN)" }
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
	{ Name "ARJ\rincomplete Address" }
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

GenericNode 53
{
	{ Name "search in Database (ini)\rfor match" }
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
	{ Name "Prefix of:\r+49532 is prefix of +49532801520\rEqual:\r+49532 is not equal +49532801520\r+49542801520 is (only) equal to +49542801520" }
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

GenericNode 83
{
	{ Name "search in Registration \rtable for CPE gateway with longest\r match (i.e. the RegTable entry\ris prefix of CdPN)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 94
{
	{ Name "ARJ calledPartyNotRegistered\rOR\rACF and route call to VoiceMail" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 95
{
	{ Name "Call to provisioned, but\rnon-registered CPE" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 104
{
	{ Name "will choose one out\rof a list of possible routes\r(honors metrics, carrier codes)" }
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

GenericEdge 15
{
	{ Name "= 0" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 1 }
	{ Subject2 5 }
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
	{ Name "CdPN is equal to \rLDAP entry's telephoneNumber" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 5 }
	{ Subject2 7 }
}

GenericEdge 21
{
	{ Name "CdPN is prefix of\rLDAP entry's telephoneNumber" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 5 }
	{ Subject2 11 }
}

GenericEdge 57
{
	{ Name "found" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 53 }
	{ Subject2 52 }
}

GenericEdge 58
{
	{ Name "not found" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 53 }
	{ Subject2 54 }
}

GenericEdge 84
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 10 }
	{ Subject2 82 }
}

GenericEdge 85
{
	{ Name "not found" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 8 }
	{ Subject2 53 }
}

GenericEdge 86
{
	{ Name "no match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 5 }
	{ Subject2 8 }
}

GenericEdge 87
{
	{ Name "\"else\" case\r(LDAP entry's telephonenumber\ris a prefix of CdPN)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 5 }
	{ Subject2 83 }
}

GenericEdge 96
{
	{ Name "found at least 1 router" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 8 }
	{ Subject2 10 }
}

GenericEdge 97
{
	{ Name "found at least 1 router" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 83 }
	{ Subject2 10 }
}

GenericEdge 98
{
	{ Name "not found" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 83 }
	{ Subject2 94 }
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
	{ Position 450 190 }
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
	{ Position 630 190 }
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
	{ Point 532 190 }
	{ Point 559 190 }
	{ NamePosition 545 180 }
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
	{ Position 790 190 }
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
	{ Point 701 190 }
	{ Point 730 190 }
	{ NamePosition 715 180 }
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
	{ Position 630 290 }
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
	{ Point 630 244 }
	{ Point 630 271 }
	{ NamePosition 616 257 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 30
{
	{ View 22 }
	{ Subject 5 }
	{ Position 450 420 }
	{ Size 232 204 }
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
	{ View 22 }
	{ Subject 15 }
	{ FromShape 23 }
	{ ToShape 30 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 450 269 }
	{ Point 450 318 }
	{ NamePosition 436 293 }
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
	{ Position 70 190 }
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
	{ Point 368 190 }
	{ Point 123 190 }
	{ NamePosition 245 180 }
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
	{ Position 90 420 }
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
	{ FromShape 30 }
	{ ToShape 34 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 334 420 }
	{ Point 179 420 }
	{ NamePosition 262 399 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 36
{
	{ View 22 }
	{ Subject 8 }
	{ Position 240 590 }
	{ Size 198 144 }
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

RoundedBox 40
{
	{ View 22 }
	{ Subject 10 }
	{ Position 480 840 }
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
	{ Position 790 420 }
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
	{ FromShape 30 }
	{ ToShape 42 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 566 420 }
	{ Point 737 420 }
	{ NamePosition 650 400 }
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
	{ Position 260 890 }
	{ Size 129 43 }
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
	{ Position 600 840 }
	{ Size 129 30 }
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
	{ Position 630 330 }
	{ Size 82 20 }
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
	{ Position 520 40 }
	{ Size 228 33 }
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
	{ Position 260 840 }
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

Diamond 60
{
	{ View 22 }
	{ Subject 53 }
	{ Position 170 740 }
	{ Size 150 110 }
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
	{ FromShape 60 }
	{ ToShape 59 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 199 773 }
	{ Point 240 817 }
	{ NamePosition 229 789 }
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
	{ Position 80 840 }
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

Line 64
{
	{ View 22 }
	{ Subject 58 }
	{ FromShape 60 }
	{ ToShape 63 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 140 773 }
	{ Point 100 817 }
	{ NamePosition 110 789 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
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
	{ Position 130 1010 }
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
	{ Position 310 1100 }
	{ Size 603 43 }
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
	{ Position 90 890 }
	{ Size 172 43 }
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
	{ Position 480 920 }
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
	{ Point 480 859 }
	{ Point 480 901 }
	{ NamePosition 466 880 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 90
{
	{ View 22 }
	{ Subject 83 }
	{ Position 620 600 }
	{ Size 208 148 }
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

Line 91
{
	{ View 22 }
	{ Subject 85 }
	{ FromShape 36 }
	{ ToShape 60 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 214 643 }
	{ Point 189 699 }
	{ NamePosition 173 663 }
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
	{ FromShape 30 }
	{ ToShape 36 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 389 468 }
	{ Point 286 552 }
	{ NamePosition 312 493 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 93
{
	{ View 22 }
	{ Subject 87 }
	{ FromShape 30 }
	{ ToShape 90 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 502 475 }
	{ Point 578 555 }
	{ NamePosition 607 489 }
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
	{ FromShape 36 }
	{ ToShape 40 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 280 632 }
	{ Point 462 821 }
	{ NamePosition 315 729 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 100
{
	{ View 22 }
	{ Subject 97 }
	{ FromShape 90 }
	{ ToShape 40 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 589 652 }
	{ Point 491 821 }
	{ NamePosition 509 696 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 101
{
	{ View 22 }
	{ Subject 94 }
	{ Position 780 840 }
	{ Size 176 42 }
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

Line 102
{
	{ View 22 }
	{ Subject 98 }
	{ FromShape 90 }
	{ ToShape 101 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 653 650 }
	{ Point 766 819 }
	{ NamePosition 720 729 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

TextBox 103
{
	{ View 22 }
	{ Subject 95 }
	{ Position 790 880 }
	{ Size 120 30 }
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

TextBox 107
{
	{ View 22 }
	{ Subject 104 }
	{ Position 630 920 }
	{ Size 146 43 }
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
	{ Position 790 470 }
	{ Size 169 43 }
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
	{ Position 80 470 }
	{ Size 131 43 }
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
	{ Position 790 240 }
	{ Size 147 43 }
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
	{ Position 80 240 }
	{ Size 144 56 }
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


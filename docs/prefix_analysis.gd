Storage 
{
	{ Format 1.31 }
	{ GeneratedFrom TGD-version-2.01 }
	{ WrittenBy nilsb }
	{ WrittenOn "Tue Jan 15 15:43:48 2002" }
}

Document 
{
	{ Type "Generic Diagram" }
	{ Name prefix_analysis.gd }
	{ Author nilsb }
	{ CreatedOn "Tue Jan 15 15:02:39 2002" }
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

Comment 1
{
	{ Name "Prefix Analysis" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 2
{
	{ Name "inc match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 3
{
	{ Name "cut off inac" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 13
{
	{ Name "ARJ\rincomplete Address" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 14
{
	{ Name "nac match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 15
{
	{ Name "cut off nac \radd county code\rof CgPN" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 16
{
	{ Name "ARJ\rincomplete Address" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 17
{
	{ Name "lac match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 18
{
	{ Name "cut off lac \radd county code\rand area code\rof CgPN" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 19
{
	{ Name "ARJ\rincomplete Address" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 20
{
	{ Name "add county code,\r area code and\rsubscriberNumber\rof CgPN" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 21
{
	{ Name "update CdPN in CallTable" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

# GRAPH EDGES

GenericEdge 5
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 1 }
	{ Subject2 2 }
}

GenericEdge 6
{
	{ Name "full match\r(i.e. inac is \rcomplete prefix\rof CdPN)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 2 }
	{ Subject2 3 }
}

GenericEdge 22
{
	{ Name "partial match\r(i.e. CdPN is shorter\rthan inac and is \rpart of inac)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 2 }
	{ Subject2 13 }
}

GenericEdge 23
{
	{ Name "no match " }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 2 }
	{ Subject2 14 }
}

GenericEdge 24
{
	{ Name "full match \r(i.e. nac is \rcomlete prefix\rof CdPN)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 14 }
	{ Subject2 15 }
}

GenericEdge 25
{
	{ Name "partial match \r(i.e. CdPN is shorter\rthan nac and is part \rof nac)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 14 }
	{ Subject2 16 }
}

GenericEdge 26
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 14 }
	{ Subject2 17 }
}

GenericEdge 27
{
	{ Name "full match \r(see above)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 17 }
	{ Subject2 18 }
}

GenericEdge 28
{
	{ Name "partial match \r(see above)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 17 }
	{ Subject2 19 }
}

GenericEdge 29
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 17 }
	{ Subject2 20 }
}

GenericEdge 30
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 20 }
	{ Subject2 21 }
}

GenericEdge 31
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 18 }
	{ Subject2 30 }
}

GenericEdge 32
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 15 }
	{ Subject2 31 }
}

GenericEdge 33
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 3 }
	{ Subject2 32 }
}

# VIEWS AND GRAPHICAL SHAPES

View 7
{
	{ Index "0" }
	{ Parent 0 }
}

TextBox 8
{
	{ View 7 }
	{ Subject 1 }
	{ Position 280 40 }
	{ Size 177 33 }
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

Diamond 9
{
	{ View 7 }
	{ Subject 2 }
	{ Position 280 130 }
	{ Size 98 54 }
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

Line 10
{
	{ View 7 }
	{ Subject 5 }
	{ FromShape 8 }
	{ ToShape 9 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 280 56 }
	{ Point 280 103 }
	{ NamePosition 266 79 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 11
{
	{ View 7 }
	{ Subject 3 }
	{ Position 500 130 }
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

Line 12
{
	{ View 7 }
	{ Subject 6 }
	{ FromShape 9 }
	{ ToShape 11 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 329 130 }
	{ Point 350 130 }
	{ Point 462 130 }
	{ NamePosition 389 100 }
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
	{ View 7 }
	{ Subject 13 }
	{ Position 60 130 }
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

Line 35
{
	{ View 7 }
	{ Subject 22 }
	{ FromShape 9 }
	{ ToShape 34 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 231 130 }
	{ Point 113 130 }
	{ NamePosition 173 98 }
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
	{ View 7 }
	{ Subject 14 }
	{ Position 280 260 }
	{ Size 98 58 }
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

Line 37
{
	{ View 7 }
	{ Subject 23 }
	{ FromShape 9 }
	{ ToShape 36 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 280 157 }
	{ Point 280 231 }
	{ NamePosition 252 183 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 38
{
	{ View 7 }
	{ Subject 15 }
	{ Position 490 260 }
	{ Size 118 54 }
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

Line 39
{
	{ View 7 }
	{ Subject 24 }
	{ FromShape 36 }
	{ ToShape 38 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 329 260 }
	{ Point 431 260 }
	{ NamePosition 376 229 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 40
{
	{ View 7 }
	{ Subject 16 }
	{ Position 60 260 }
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

Line 41
{
	{ View 7 }
	{ Subject 25 }
	{ FromShape 36 }
	{ ToShape 40 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 231 260 }
	{ Point 113 260 }
	{ NamePosition 172 230 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 42
{
	{ View 7 }
	{ Subject 17 }
	{ Position 280 390 }
	{ Size 96 58 }
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
	{ View 7 }
	{ Subject 26 }
	{ FromShape 36 }
	{ ToShape 42 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 280 289 }
	{ Point 280 361 }
	{ NamePosition 266 325 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 44
{
	{ View 7 }
	{ Subject 18 }
	{ Position 490 390 }
	{ Size 118 54 }
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

Line 45
{
	{ View 7 }
	{ Subject 27 }
	{ FromShape 42 }
	{ ToShape 44 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 328 390 }
	{ Point 431 390 }
	{ NamePosition 377 372 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 46
{
	{ View 7 }
	{ Subject 19 }
	{ Position 60 390 }
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

Line 47
{
	{ View 7 }
	{ Subject 28 }
	{ FromShape 42 }
	{ ToShape 46 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 232 390 }
	{ Point 113 390 }
	{ NamePosition 172 374 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 48
{
	{ View 7 }
	{ Subject 20 }
	{ Position 490 540 }
	{ Size 118 54 }
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

Line 49
{
	{ View 7 }
	{ Subject 29 }
	{ FromShape 42 }
	{ ToShape 48 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 280 419 }
	{ Point 280 530 }
	{ Point 431 530 }
	{ NamePosition 266 474 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 50
{
	{ View 7 }
	{ Subject 21 }
	{ Position 550 660 }
	{ Size 144 38 }
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

Line 51
{
	{ View 7 }
	{ Subject 30 }
	{ FromShape 48 }
	{ ToShape 50 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 549 540 }
	{ Point 590 540 }
	{ Point 590 641 }
	{ NamePosition 569 530 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 52
{
	{ View 7 }
	{ Subject 31 }
	{ FromShape 44 }
	{ ToShape 51 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 549 380 }
	{ Point 590 380 }
	{ Point 590 540 }
	{ NamePosition 569 370 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 53
{
	{ View 7 }
	{ Subject 32 }
	{ FromShape 38 }
	{ ToShape 52 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 549 260 }
	{ Point 590 260 }
	{ Point 590 380 }
	{ NamePosition 569 250 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 54
{
	{ View 7 }
	{ Subject 33 }
	{ FromShape 11 }
	{ ToShape 53 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 538 130 }
	{ Point 590 130 }
	{ Point 590 260 }
	{ NamePosition 564 120 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}


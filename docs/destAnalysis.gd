Storage 
{
	{ Format 1.31 }
	{ GeneratedFrom TGD-version-2.01 }
	{ WrittenBy mmuehlen }
	{ WrittenOn "Tue Apr 30 13:31:20 2002" }
}

Document 
{
	{ Type "Generic Diagram" }
	{ Name destAnalysis.gd }
	{ Author mmuehlen }
	{ CreatedOn "Mon Jan 14 16:04:47 2002" }
	{ Annotation "" }
}

Page 
{
	{ PageOrientation Landscape }
	{ PageSize A4 }
	{ ShowHeaders False }
	{ ShowFooters False }
	{ ShowNumbers False }
}

Scale 
{
	{ ScaleValue 0.812583 }
}

# GRAPH NODES

GenericNode 1
{
	{ Name "ARQ" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 2
{
	{ Name "trunk gateway?" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 7
{
	{ Name "match CdPN left-justified\ragainst voIPspecialDial\r(left hand side)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 8
{
	{ Name "Prefix Analysis\r(see special diagram)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 9
{
	{ Name "save dialed CdPN and\rreal/international CdPN\rin CallTable" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

Comment 131
{
	{ Name "Destination Analysis" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 133
{
	{ Name "number conversions\r(see special diagram)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 143
{
	{ Name "routing decision\r(see special diagram)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 147
{
	{ Name "gateway honors \rARJ incompleteAddress\r= TRUE ?" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 17
{
	{ Name "ARJ\rincompleteAddress" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 154
{
	{ Name "ACF" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 155
{
	{ Name "gateway honors \rARJ incompleteAddress\r= TRUE ?" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 156
{
	{ Name "ARJ\rincompleteAddress" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 157
{
	{ Name "ACF" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 172
{
	{ Name "try to\rget calling profile\rfrom database" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 173
{
	{ Name "profile exists?" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 174
{
	{ Name "add country code\rto CdPN" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 175
{
	{ Name "section \rfor used databases\rexists in ini file" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

GenericNode 176
{
	{ Name "ARJ\rcallerNotRegistered\r(Provisioning error !)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Index "" }
}

# GRAPH EDGES

GenericEdge 101
{
	{ Name "prefix not unique\r(eg. only '0' dialed)" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 8 }
	{ Subject2 147 }
}

GenericEdge 144
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 133 }
	{ Subject2 143 }
}

GenericEdge 159
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 147 }
	{ Subject2 154 }
}

GenericEdge 160
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 155 }
	{ Subject2 156 }
}

GenericEdge 162
{
	{ Name "partial match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 7 }
	{ Subject2 155 }
}

GenericEdge 177
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 172 }
	{ Subject2 173 }
}

GenericEdge 178
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 2 }
	{ Subject2 174 }
}

GenericEdge 180
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 1 }
	{ Subject2 172 }
}

GenericEdge 181
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 173 }
	{ Subject2 2 }
}

GenericEdge 183
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 173 }
	{ Subject2 175 }
}

GenericEdge 184
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 2 }
	{ Subject2 7 }
}

GenericEdge 185
{
	{ Name "no match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 7 }
	{ Subject2 8 }
}

GenericEdge 187
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 147 }
	{ Subject2 17 }
}

GenericEdge 188
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 155 }
	{ Subject2 157 }
}

GenericEdge 211
{
	{ Name "no" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 175 }
	{ Subject2 133 }
}

GenericEdge 212
{
	{ Name "yes" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 175 }
	{ Subject2 176 }
}

GenericEdge 213
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 174 }
	{ Subject2 133 }
}

GenericEdge 222
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 9 }
	{ Subject2 133 }
}

GenericEdge 232
{
	{ Name "" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 8 }
	{ Subject2 9 }
}

GenericEdge 233
{
	{ Name "full match" }
	{ Annotation "" }
	{ Parent 0 }
	{ Subject1 7 }
	{ Subject2 9 }
}

# VIEWS AND GRAPHICAL SHAPES

View 50
{
	{ Index "0" }
	{ Parent 0 }
}

RoundedBox 51
{
	{ View 50 }
	{ Subject 1 }
	{ Position 510 110 }
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

Diamond 52
{
	{ View 50 }
	{ Subject 2 }
	{ Position 680 300 }
	{ Size 170 64 }
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
	{ View 50 }
	{ Subject 8 }
	{ Position 610 470 }
	{ Size 204 58 }
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

Box 68
{
	{ View 50 }
	{ Subject 9 }
	{ Position 720 580 }
	{ Size 274 48 }
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

Line 105
{
	{ View 50 }
	{ Subject 101 }
	{ FromShape 65 }
	{ ToShape 150 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 508 470 }
	{ Point 420 470 }
	{ Point 420 494 }
	{ NamePosition 464 460 }
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
	{ View 50 }
	{ Subject 7 }
	{ Position 790 400 }
	{ Size 162 86 }
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

TextBox 132
{
	{ View 50 }
	{ Subject 131 }
	{ Position 580 60 }
	{ Size 240 33 }
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

Box 137
{
	{ View 50 }
	{ Subject 133 }
	{ Position 240 700 }
	{ Size 228 36 }
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

Box 145
{
	{ View 50 }
	{ Subject 143 }
	{ Position 240 760 }
	{ Size 98 40 }
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

Line 146
{
	{ View 50 }
	{ Subject 144 }
	{ FromShape 137 }
	{ ToShape 145 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 240 718 }
	{ Point 240 740 }
	{ NamePosition 226 729 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 150
{
	{ View 50 }
	{ Subject 147 }
	{ Position 420 530 }
	{ Size 157 72 }
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

EllipsedBox 83
{
	{ View 50 }
	{ Subject 17 }
	{ Position 350 600 }
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

EllipsedBox 164
{
	{ View 50 }
	{ Subject 154 }
	{ Position 500 600 }
	{ Size 112 38 }
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

Line 165
{
	{ View 50 }
	{ Subject 159 }
	{ FromShape 150 }
	{ ToShape 164 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 498 530 }
	{ Point 510 530 }
	{ Point 510 581 }
	{ NamePosition 504 520 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 166
{
	{ View 50 }
	{ Subject 155 }
	{ Position 1020 480 }
	{ Size 157 72 }
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

EllipsedBox 167
{
	{ View 50 }
	{ Subject 156 }
	{ Position 940 580 }
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

Line 168
{
	{ View 50 }
	{ Subject 160 }
	{ FromShape 166 }
	{ ToShape 167 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 942 480 }
	{ Point 930 480 }
	{ Point 930 561 }
	{ NamePosition 936 470 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

EllipsedBox 169
{
	{ View 50 }
	{ Subject 157 }
	{ Position 1080 580 }
	{ Size 112 38 }
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

Line 171
{
	{ View 50 }
	{ Subject 162 }
	{ FromShape 121 }
	{ ToShape 166 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 871 400 }
	{ Point 1020 400 }
	{ Point 1020 444 }
	{ NamePosition 945 390 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 189
{
	{ View 50 }
	{ Subject 172 }
	{ Position 510 170 }
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

Diamond 190
{
	{ View 50 }
	{ Subject 173 }
	{ Position 510 240 }
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

Line 191
{
	{ View 50 }
	{ Subject 177 }
	{ FromShape 189 }
	{ ToShape 190 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 189 }
	{ Point 510 221 }
	{ NamePosition 496 205 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Box 192
{
	{ View 50 }
	{ Subject 174 }
	{ Position 280 380 }
	{ Size 99 38 }
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

Line 193
{
	{ View 50 }
	{ Subject 178 }
	{ FromShape 52 }
	{ ToShape 192 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 595 300 }
	{ Point 280 300 }
	{ Point 280 361 }
	{ NamePosition 437 290 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Diamond 194
{
	{ View 50 }
	{ Subject 175 }
	{ Position 180 310 }
	{ Size 156 68 }
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

EllipsedBox 196
{
	{ View 50 }
	{ Subject 176 }
	{ Position 90 420 }
	{ Size 152 52 }
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

Line 197
{
	{ View 50 }
	{ Subject 180 }
	{ FromShape 51 }
	{ ToShape 189 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 510 129 }
	{ Point 510 151 }
	{ NamePosition 496 140 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 198
{
	{ View 50 }
	{ Subject 181 }
	{ FromShape 190 }
	{ ToShape 52 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 548 240 }
	{ Point 680 240 }
	{ Point 680 268 }
	{ NamePosition 614 230 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 200
{
	{ View 50 }
	{ Subject 183 }
	{ FromShape 190 }
	{ ToShape 194 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 472 240 }
	{ Point 180 240 }
	{ Point 180 276 }
	{ NamePosition 326 230 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 201
{
	{ View 50 }
	{ Subject 184 }
	{ FromShape 52 }
	{ ToShape 121 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 765 300 }
	{ Point 790 300 }
	{ Point 790 357 }
	{ NamePosition 777 290 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 202
{
	{ View 50 }
	{ Subject 185 }
	{ FromShape 121 }
	{ ToShape 65 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 709 400 }
	{ Point 610 400 }
	{ Point 610 441 }
	{ NamePosition 659 390 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 204
{
	{ View 50 }
	{ Subject 187 }
	{ FromShape 150 }
	{ ToShape 83 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 342 530 }
	{ Point 330 530 }
	{ Point 330 581 }
	{ NamePosition 336 520 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 205
{
	{ View 50 }
	{ Subject 188 }
	{ FromShape 166 }
	{ ToShape 169 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 1098 480 }
	{ Point 1110 480 }
	{ Point 1109 561 }
	{ NamePosition 1104 470 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 216
{
	{ View 50 }
	{ Subject 211 }
	{ FromShape 194 }
	{ ToShape 137 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 184 341 }
	{ Point 186 682 }
	{ NamePosition 198 511 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 217
{
	{ View 50 }
	{ Subject 212 }
	{ FromShape 194 }
	{ ToShape 196 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 3 }
	{ Point 102 310 }
	{ Point 70 310 }
	{ Point 70 394 }
	{ NamePosition 86 300 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 218
{
	{ View 50 }
	{ Subject 213 }
	{ FromShape 192 }
	{ ToShape 137 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 278 399 }
	{ Point 267 682 }
	{ NamePosition 259 540 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 225
{
	{ View 50 }
	{ Subject 222 }
	{ FromShape 68 }
	{ ToShape 137 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 4 }
	{ Point 720 604 }
	{ Point 720 650 }
	{ Point 320 650 }
	{ Point 320 682 }
	{ NamePosition 520 640 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 234
{
	{ View 50 }
	{ Subject 232 }
	{ FromShape 65 }
	{ ToShape 68 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 639 499 }
	{ Point 660 556 }
	{ NamePosition 662 524 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}

Line 235
{
	{ View 50 }
	{ Subject 233 }
	{ FromShape 121 }
	{ ToShape 68 }
	{ Curved False }
	{ End1 Empty }
	{ End2 FilledArrow }
	{ Points 2 }
	{ Point 790 443 }
	{ Point 780 556 }
	{ NamePosition 772 499 }
	{ Color "black" }
	{ LineWidth 1 }
	{ LineStyle Solid }
	{ FixedName False }
	{ Font "-*-helvetica-medium-r-normal--10*" }
	{ TextAlignment Center }
	{ TextColor "black" }
	{ NameUnderlined False }
}


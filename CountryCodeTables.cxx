// -*- mode: c++; eval: (c-set-style "linux"); -*-
// Copyright (C) 2002 Dr.-Ing. Martin Froehlich <Martin.Froehlich@mediaWays.net>
//  
// PURPOSE OF THIS FILE:
//    some static tables with standardizes information for reference lookup
//  
// - Automatic Version Information via RCS:
//   $Id$
//   $Source$
//  
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//  
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//  
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
//

#include <stddef.h>
#include "CountryCodeTables.h"

using namespace ITU_T_E164_CodeTables;
int a(){return 0;};
const DictInitializer ITU_T_E164_CodeTables::AssignedCountyCodes[] = {
	{"0","Reserved"},		/* NOTE: a */
	//{"1","Anguilla"},		/* NOTE: b */
	//{"1","Antigua and Barbuda"},	/* NOTE: b */
	//{"1","Bahamas (Commonwealth of the)"}, /* NOTE: b */
	//{"1","Barbados"},		/* NOTE: b */
	//{"1","Bermuda"},		/* NOTE: b */
	//{"1","British Virgin Islands"}, /* NOTE: b */
	//{"1","Canada"},		/* NOTE: b */
	//{"1","Cayman Islands"},	/* NOTE: b */
	//{"1","Dominica (Commonwealth of)"}, /* NOTE: b */
	//{"1","Dominican Republic"},	/* NOTE: b */
	//{"1","Grenada"},		/* NOTE: b */
	//{"1","Guam"},			/* NOTE: b */
	//{"1","Jamaica"},		/* NOTE: b */
	//{"1","Montserrat"},		/* NOTE: b */
	//{"1","Northern Mariana Islands (Commonwealth of the)"}, /* NOTE: b */
	//{"1","Puerto Rico"},		/* NOTE: b */
	//{"1","Saint Kitts and Nevis"}, /* NOTE: b */
	//{"1","Saint Lucia"},		/* NOTE: b */
	//{"1","Saint Vincent and the Grenadines"}, /* NOTE: b */
	//{"1","Trinidad and Tobago"},	/* NOTE: b */
	//{"1","Turks and Caicos Islands"}, /* NOTE: b */
	//{"1","United States of America et al."}, /* NOTE: b */
	//{"1","United States Virgin Islands"},	/* NOTE: b */
	{"1","Integrated Numbering Plan: U.S.A et al."}, /* NOTE: b2 */
	{"20","Egypt (Arab Republic of)"},
	{"210","Spare code"},
	{"211","Spare code"},
	{"212","Morocco (Kingdom of)"},
	{"213","Algeria (People's Democratic Republic of)"},
	{"214","Spare code"},
	{"215","Spare code"},
	{"216","Tunisia"},
	{"217","Spare code"},
	{"218","Libya (Socialist People's Libyan Arab Jamahiriya)"},
	{"219","Spare code"},
	{"220","Gambia (Republic of the)"},
	{"221","Senegal (Republic of)"},
	{"222","Mauritania (Islamic Republic of)"},
	{"223","Mali (Republic of)"},
	{"224","Guinea (Republic of)"},
	{"225","Co^te d'Ivoire (Republic of)"},
	{"226","Burkina Faso"},
	{"227","Niger (Republic of the)"},
	{"228","Togolese Republic"},
	{"229","Benin (Republic of)"},
	{"230","Mauritius (Republic of)"},
	{"231","Liberia (Republic of)"},
	{"232","Sierra Leone"},
	{"233","Ghana"},
	{"234","Nigeria (Federal Republic of)"},
	{"235","Chad (Republic of)"},
	{"236","Central African Republic"},
	{"237","Cameroon (Republic of)"},
	{"238","Cape Verde (Republic of)"},
	{"239","Sao Tome and Principe (Democratic Republic of)"},
	{"240","Equatorial Guinea (Republic of)"},
	{"241","Gabonese Republic"},
	{"242","Congo (Republic of the)"},
	{"243","Democratic Republic of the Congo"},
	{"244","Angola (Republic of)"},
	{"245","Guinea-Bissau (Republic of)"},
	{"246","Diego Garcia"},
	{"247","Ascension"},
	{"248","Seychelles (Republic of)"},
	{"249","Sudan (Republic of the)"},
	{"250","Rwandese Republic"},
	{"251","Ethiopia (Federal Democratic Republic of)"},
	{"252","Somali Democratic Republic"},
	{"253","Djibouti (Republic of)"},
	{"254","Kenya (Republic of)"},
	{"255","Tanzania (United Republic of)"},
	{"256","Uganda (Republic of)"},
	{"257","Burundi (Republic of)"},
	{"258","Mozambique (Republic of)"},
	{"259","Spare code"},
	{"260","Zambia (Republic of)"},
	{"261","Madagascar (Republic of)"},
	{"262","Reunion (French Department of)"},
	{"263","Zimbabwe (Republic of)"},
	{"264","Namibia (Republic of)"},
	{"265","Malawi"},
	{"266","Lesotho (Kingdom of)"},
	{"267","Botswana (Republic of)"},
	{"268","Swaziland (Kingdom of)"},
	//{"269","Comoros (Islamic Federal Republic of the)"}, /* NOTE: c */
	//{"269","Mayotte (Collectivite' territoriale de la Re'publique franc,aise)"}, /* NOTE: c */
	{"269","Comoros & Mayotte Shared Code"}, /* NOTE: b2 */
	{"27","South Africa (Republic of)"},
	{"280","Spare code"},		/* NOTE: m */
	{"281","Spare code"},		/* NOTE: m */
	{"282","Spare code"},		/* NOTE: m */
	{"283","Spare code"},		/* NOTE: m */
	{"284","Spare code"},		/* NOTE: m */
	{"285","Spare code"},		/* NOTE: m */
	{"286","Spare code"},		/* NOTE: m */
	{"287","Spare code"},		/* NOTE: m */
	{"288","Spare code"},		/* NOTE: m */
	{"289","Spare code"},		/* NOTE: m */
	{"290","Saint Helena"},
	{"291","Eritrea"},
	{"292","Spare code"},
	{"293","Spare code"},
	{"294","Spare code"},
	{"295","Spare code"},
	{"296","Spare code"},
	{"297","Aruba"},
	{"298","Faroe Islands (Denmark)"},
	{"299","Greenland (Denmark)"},
	{"30","Greece"},
	{"31","Netherlands (Kingdom of the)"},
	{"32","Belgium"},
	{"33","France"},
	{"34","Spain"},
	{"350","Gibraltar"},
	{"351","Portugal"},
	{"352","Luxembourg"},
	{"353","Ireland"},
	{"354","Iceland"},
	{"355","Albania (Republic of)"},
	{"356","Malta"},
	{"357","Cyprus (Republic of)"},
	{"358","Finland"},
	{"359","Bulgaria (Republic of)"},
	{"36","Hungary (Republic of)"},
	{"370","Lithuania (Republic of)"},
	{"371","Latvia (Republic of)"},
	{"372","Estonia (Republic of)"},
	{"373","Moldova (Republic of)"},
	{"374","Armenia (Republic of)"},
	{"375","Belarus (Republic of)"},
	{"376","Andorra (Principality of)"},
	{"377","Monaco (Principality of)"},
	{"378","San Marino (Republic of)"},
	{"379","Vatican City State"},	/* NOTE: f */
	{"380","Ukraine"},
	{"381","Yugoslavia (Federal Republic of)"},
	{"382","Spare code"},
	{"383","Spare code"},
	{"384","Spare code"},
	{"385","Croatia (Republic of)"},
	{"386","Slovenia (Republic of)"},
	{"387","Bosnia and Herzegovina (Republic of)"},
	{"388","Reserved - for ETNS (European Telephony Numbering Space) trial"},
	{"389","The Former Yugoslav Republic of Macedonia"},
	//{"39","Italy"},		/* NOTE: 2b */
	//{"39","Vatican City State"}, /* NOTE: 2b */
	{"39","Italy & Vatican City State"},
	{"40","Romania"},
	{"41","Switzerland (Confederation of)"},
	{"420","Czech Republic"},
	{"421","Slovak Republic"},
	{"422","Spare code"},
	{"423","Liechtenstein (Principality of)"},
	{"424","Spare code"},
	{"425","Spare code"},
	{"426","Spare code"},
	{"427","Spare code"},
	{"428","Spare code"},
	{"429","Spare code"},
	{"43","Austria"},
	{"44","United Kingdom of Great Britain and Northern Ireland"},
	{"45","Denmark"},
	{"46","Sweden"},
	{"47","Norway"},
	{"48","Poland (Republic of)"},
	{"49","Germany (Federal Republic of)"},
	{"500","Falkland Islands (Malvinas)"},
	{"501","Belize"},
	{"502","Guatemala (Republic of)"},
	{"503","El Salvador (Republic of)"},
	{"504","Honduras (Republic of)"},
	{"505","Nicaragua    506  Costa Rica"},
	{"507","Panama (Republic of)"},
	{"508","Saint Pierre and Miquelon (Collectivite' territoriale de la Re'publique franc,aise)"},
	{"509","Haiti (Republic of)"},
	{"51","Peru"},
	{"52","Mexico"},
	{"53","Cuba"},
	{"54","Argentine Republic"},
	{"55","Brazil (Federative Republic of)"},
	{"56","Chile"},
	{"57","Colombia (Republic of)"},
	{"58","Venezuela (Republic of)"},
	{"590","Guadeloupe (French Department of)"},
	{"591","Bolivia (Republic of)"},
	{"592","Guyana"},
	{"593","Ecuador"},
	{"594","Guiana (French Department of)"},
	{"595","Paraguay (Republic of)"},
	{"596","Martinique (French Department of)"},
	{"597","Suriname (Republic of)"},
	{"598","Uruguay (Eastern Republic of)"},
	{"599","Netherlands Antilles"},
	{"60","Malaysia"},
	{"61","Australia"},		/* NOTE: i */
	{"62","Indonesia (Republic of)"},
	{"63","Philippines (Republic of the)"},
	{"64","New Zealand"},
	{"65","Singapore (Republic of)"},
	{"66","Thailand"},
	{"670","Spare code"},
	{"671","Spare code"},
	{"672","Australian External Territories"}, /* NOTE: g */
	{"673","Brunei Darussalam"},
	{"674","Nauru (Republic of)"},
	{"675","Papua New Guinea"},
	{"676","Tonga (Kingdom of)"},
	{"677","Solomon Islands"},
	{"678","Vanuatu (Republic of)"},
	{"679","Fiji (Republic of)"},
	{"680","Palau (Republic of)"},
	{"681","Wallis and Futuna (Territoire franc,ais d'outre-mer)"},
	{"682","Cook Islands"},
	{"683","Niue"},
	{"684","American Samoa"},
	{"685","Western Samoa (Independent State of)"},
	{"686","Kiribati (Republic of)"},
	{"687","New Caledonia (Territoire franc,ais d'outre-mer)"},
	{"688","Tuvalu"},
	{"689","French Polynesia (Territoire franc,ais d'outre-mer)"},
	{"690","Tokelau"},
	{"691","Micronesia (Federated States of)"},
	{"692","Marshall Islands (Republic of the)"},
	{"693","Spare code"},
	{"694","Spare code"},
	{"695","Spare code"},
	{"696","Spare code"},
	{"697","Spare code"},
	{"698","Spare code"},
	{"699","Spare code"},
	//{"7","Kazakstan (Republic of)"}, /* NOTE: b */
	//{"7","Russian Federation"},	/* NOTE: b */
	//{"7","Tajikistan (Republic of)"}, /* NOTE: b */
	{"7","Integrated Numbering Plan: Russian Federation et al."}, /* NOTE: b2 */
	{"800","International Freephone Service"},
	{"801","Spare code"},		/* NOTE: d */
	{"802","Spare code"},		/* NOTE: d */
	{"803","Spare code"},		/* NOTE: d */
	{"804","Spare code"},		/* NOTE: d */
	{"805","Spare code"},		/* NOTE: d */
	{"806","Spare code"},		/* NOTE: d */
	{"807","Spare code"},		/* NOTE: d */
	{"808","Reserved for International Shared Cost Service (ISCS)"},
	{"809","Spare code"},		/* NOTE: d */
	{"81","Japan"},
	{"82","Korea (Republic of)"},
	{"830","Spare code"},		/* NOTE: m */
	{"831","Spare code"},		/* NOTE: m */
	{"832","Spare code"},		/* NOTE: m */
	{"833","Spare code"},		/* NOTE: m */
	{"834","Spare code"},		/* NOTE: m */
	{"835","Spare code"},		/* NOTE: m */
	{"836","Spare code"},		/* NOTE: m */
	{"837","Spare code"},		/* NOTE: m */
	{"838","Spare code"},		/* NOTE: m */
	{"839","Spare code"},		/* NOTE: m */
	{"84","Viet Nam (Socialist Republic of)"},
	{"850","Democratic People's Republic of Korea"},
	{"851","Spare code"},
	{"852","Hongkong"},
	{"853","Macau"},
	{"854","Spare code"},
	{"855","Cambodia (Kingdom of)"},
	{"856","Lao People's Democratic Republic"},
	{"857","Spare code"},
	{"858","Spare code"},
	{"859","Spare code"},
	{"86","China (People's Republic of)"},
	{"870","Inmarsat SNAC"},
	{"871","Inmarsat (Atlantic Ocean-East)"},
	{"872","Inmarsat (Pacific Ocean)"},
	{"873","Inmarsat (Indian Ocean)"},
	{"874","Inmarsat (Atlantic Ocean-West)"},
	{"875","Reserved - Maritime Mobile Service Applications"},
	{"876","Reserved - Maritime Mobile Service Applications"},
	{"877","Reserved - Maritime Mobile Service Applications"},
	{"878","Reserved - Universal Personal Telecommunication Service (UPT)"}, /* NOTE: e */
	{"879","Reserved for national purposes"},
	{"880","Bangladesh (People's Republic of)"},
	{"881","Global Mobile Satellite System (GMSS), shared code"},	/* NOTE: k */
	{"882","International Networks, shared code"}, /* NOTE: j */
	{"883","Spare code"},
	{"884","Spare code"},
	{"885","Spare code"},
	{"886","Reserved"},
	{"887","Spare code"},
	{"888","SERVICE: Reserved for future global service"},
	{"889","Spare code"},
	{"890","Spare code"},		/* NOTE: m */
	{"891","Spare code"},		/* NOTE: m */
	{"892","Spare code"},		/* NOTE: m */
	{"893","Spare code"},		/* NOTE: m */
	{"894","Spare code"},		/* NOTE: m */
	{"895","Spare code"},		/* NOTE: m */
	{"896","Spare code"},		/* NOTE: m */
	{"897","Spare code"},		/* NOTE: m */
	{"898","Spare code"},		/* NOTE: m */
	{"899","Spare code"},		/* NOTE: m */
	{"90","Turkey"},
	{"91","India (Republic of)"},
	{"92","Pakistan (Islamic Republic of)"},
	{"93","Afghanistan (Islamic State of)"},
	{"94","Sri Lanka (Democratic Socialist Republic of)"},
	{"95","Myanmar (Union of)"},
	{"960","Maldives (Republic of)"},
	{"961","Lebanon"},
	{"962","Jordan (Hashemite Kingdom of)"},
	{"963","Syrian Arab Republic"},
	{"964","Iraq (Republic of)"},
	{"965","Kuwait (State of)"},
	{"966","Saudi Arabia (Kingdom of)"},
	{"967","Yemen (Republic of)"},
	{"968","Oman (Sultanate of)"},
	{"969","Reserved - reservation currently under investigation"},
	{"970","Reserved"},		/* NOTE: l */
	{"971","United Arab Emirates"}, /* NOTE: h */
	{"972","Israel (State of)"},
	{"973","Bahrain (State of)"},
	{"974","Qatar (State of)"},
	{"975","Bhutan (Kingdom of)"},
	{"976","Mongolia"},
	{"977","Nepal"},
	{"978","Spare code"},
	{"979","SERVICE: Reserved for the International Premium Rate Service (IPRS)"},
	{"98","Iran (Islamic Republic of)"},
	{"990","Spare code"},
	{"991","Spare code"},
	{"992","Tajikistan (Republic of)"}, /* NOTE: f */
	{"993","Turkmenistan"},
	{"994","Azerbaijani Republic"},
	{"995","Georgia"},
	{"996","Kyrgyz Republic"},
	{"997","Spare code"},
	{"998","Uzbekistan (Republic of)"},
	{"999","Spare code"},
	{NULL,NULL}
	/** Notes:
	 * a Assignment of all 0XX codes will be feasible after 31 December
	 *   2000. Assignment of some of these codes may be possible as soon as 1
	 *   January 1997; this question is currently under study.
	 * b Integrated numbering plan.
	 * b2 Own unifiying entry, not in ITU-T E.164 !
	 * c Code shared between Mayotte Island and Comoros (Islamic Federal
	 *   Republic of the).
	 * d Will be allocated, only after all three digit codes from groups of ten
	 *   are exhausted.
	 * e ITU-T Study Group 2, at its meeting in May 1996, has agreed that E.164
	 *   country code '878' is reserved for future use by the Universal Personal
	 *   Telecommunication Service (UPT). The purpose of this announcement is to
	 *   recommend that administrations and Recognized Operating Agencies (ROAs)
	 *   do not use this country code for national purposes, e.g. testing.
	 * f Reserved for future use.
	 * g Including Australian Antartic Territory Bases, Christmas Island and
	 *   Norfolk Island.
	 * h U.A.E.: Abu Dhabi, Ajman, Dubai, Fujeirah, Ras Al Khaimah, Sharjah,
	 *   Umm Al Qaiwain.
	 * i Including Cocos-Keeling Islands.
	 * j Associated with shared country code 882, two-digit identification
	 *   codes reservations or assignments have been made for the
	 *   international networks
	 * k Associated with shared country code 881, the following one-digit
	 *   identification code have been made for the GMSS networks
	 * l Reserved for the Palestinian Authority.
	 * m Reserved for E.164 country code expansion.
	 */
};

const DictInitializer ITU_T_E164_CodeTables::AssignedNetworkIdentificationCode[] = {
	{"10","assigned to British Telecommunications plc [Global Office Application]"},
	{"11","reserved for Singapore Telecommunications Pte Ltd (ST) [Asia Pacific Mobile Telecommunications (APMT)]"},
	{"12","reserved for MCI [HyperStream International (HSI) Data Network]"},
	{"13","assigned to Telespazio S.p.A. [EMS Regional Mobile Satellite System]"},
	{"14","reserved for GTE [GTE International Networks]"},
	{"15","reserved for Telstra [ITERRA Digital Network]"},
	{"16","reserved for United Arab Emirates Administration [Thuraya RMSS Network]"},
	{"17","reserved for AT&T [AT&T International ATM Network]"},
	{"18","reserved for Teledesic [Teledesic Global Network]"},
	{"19","reserved for Telecom Italia [Telecom Italia Global Network]"},
	{"20","reserved for Asia Cellular Satellite (ACeS) [Garuda Mobile Telecommunication Satellite System]"},
	{"21","reserved for Ameritech [Ameritech s Gateway Global Service, Inc. (AGGSI) network]"},
	{"22","assigned to Cable & Wireless plc [Cable & Wireless Global Network]"},
	{"23","reserved for Sita-Equant Joint Venture [Sita-Equant Network]"},
	{"24","reserved for Telia AB [Telia multinational ATM Network]"},
	{"25","reserved for Constellation Communications, Inc. [Constellation System]"},
	{NULL,NULL}
};

const DictInitializer ITU_T_E164_CodeTables::AssignedGMSSNetworkIdentificationCode[] = {
	{"0","reserved for ICO Global Comminications"},
	{"1","reserved for ICO Global Comminications"},
	{"6","assigned to Iridium"},
	{"7","assigned to Iridium"},
	{"8","reserved for Globalstar"},
	{"9","reserved for Globalstar"},
	{NULL,NULL}
};

// End of $Source$

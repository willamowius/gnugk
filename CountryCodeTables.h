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

#if !defined(COUNTRYCODESTABLES_H) /* make idempotent */
#define COUNTRYCODESTABLES_H "@(#) $Id$"

namespace ITU_T_E164_CodeTables {
	// The structure for the following lists, they are {NULL,NULL}-pair
	// terminated and absolutely constant
	typedef struct DictInitializer {
		const char * key;
		const char * value;
	} DictInitializer;

	extern const DictInitializer AssignedCountyCodes[];
	extern const DictInitializer AssignedNetworkIdentificationCode[];
	extern const DictInitializer AssignedGMSSNetworkIdentificationCode[];
}

#endif /* defined(COUNTRYCODESTABLES_H) */

//
// End of CountryCodesTables.h
//

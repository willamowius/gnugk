//////////////////////////////////////////////////////////////////
//
// main.cxx creation of the process
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
//////////////////////////////////////////////////////////////////

/*
 * You have to create a process with your own Gatekeeper class.
 * I choosed to make it this way. Alternatively you do use
 * your own "main.cxx" file and link that to yout binary instead
 * of this file.
 */


#include <ptlib.h>
#include "gk.h"

PCREATE_PROCESS(Gatekeeper)

// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// ANSI.h  -- Ansi color definitions
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      991215  initial Version (Torsten Will, mediaWays)
//
//////////////////////////////////////////////////////////////////

#ifndef ANSI_H
#define ANSI_H "@(#) $Id$"

/** You can disable the use of ANSI codes at compile time
 * defining GK_NOANSI
 */
#ifdef GK_NOANSI
#define _ANSI(f) ""
#else
#define _ANSI(f) f
#endif


/** Class that groups ansi codes together.
 * Declares common ANSI colors and colors for special output.
 *
 * @author Torsten Will, mediaways
 * @date 99/12/22
 */
namespace ANSI
{
  ///@name Colors
  ///@{
  const static char * const OFF = _ANSI("\033[m");   /// reset
  const static char * const BLD = _ANSI("\033[1m");  /// bright/bold

  const static char * const BLA = _ANSI("\033[30m"); /// black
  const static char * const RED = _ANSI("\033[31m"); /// red
  const static char * const GRE = _ANSI("\033[32m"); /// green
  const static char * const YEL = _ANSI("\033[33m"); /// yellow
  const static char * const BLU = _ANSI("\033[34m"); /// blue
  const static char * const PIN = _ANSI("\033[35m"); /// pink
  const static char * const CYA = _ANSI("\033[36m"); /// cyan

  const static char * const BBLA = _ANSI("\033[1m\033[30m"); /// bright/bold black
  const static char * const BRED = _ANSI("\033[1m\033[31m"); /// b red
  const static char * const BGRE = _ANSI("\033[1m\033[32m"); /// b green
  const static char * const BYEL = _ANSI("\033[1m\033[33m"); /// b yellow
  const static char * const BBLU = _ANSI("\033[1m\033[34m"); /// b blue
  const static char * const BPIN = _ANSI("\033[1m\033[35m"); /// b pink
  const static char * const BCYA = _ANSI("\033[1m\033[36m"); /// b cyan
  ///@}

  ///@name Common
  ///@{
  const static char * const DBG = BLU;  /// debug
  ///@}

};

#endif // ANSI_H

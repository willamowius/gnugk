/* -*- mode: c++; eval: (c-set-style "linux"); -*-
** Copyright (C) 2002 Dr.-Ing. Martin Froehlich <Martin.Froehlich@mediaWays.net>
**
** PURPOSE OF THIS FILE: PWLib conform versioning
**
** WARNING: This file is edited automatically by the makefile, if opened by
**          an editor, reload from disk before adding own changes!
**
** Note: Do not add spaces manually between macros and their values, that
** may lead to not nice design of some markers and makes tham difficult to
** quote correctly in e.g. a debugger
**
** - Automatic Version Information via RCS:
**   $Id$
**   $Source$
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#ifndef GNUGK_VERSION_H
#define GNUGK_VERSION_H

/* Major version number of the gatekeeper */
#ifndef MAJOR_VERSION
#define MAJOR_VERSION 2
#endif

/* Minor version number of the gatekeeper */
#ifndef MINOR_VERSION
#define MINOR_VERSION 1
#endif

/* Release status for the gatekeeper */
#ifndef BUILD_TYPE
/* might be: AlphaCode, BetaCode, ReleaseCode */
#define BUILD_TYPE AlphaCode
/* Set this Macro if Release Code */
#ifdef RELEASE_CODE
# undef RELEASE_CODE
#endif
#endif

/* Build number of the gatekeeper */
#ifndef BUILD_NUMBER
#define BUILD_NUMBER 22
#endif

#endif  /* GNUGK_VERSION_H */

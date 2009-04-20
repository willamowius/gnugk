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
** it under the terms of the GNU General Public License version 2 as published by
** the Free Software Foundation.
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
#define GNUGK_VERSION_H "@(#) $Id$"

/* Major version number of the gatekeeper */
#ifndef GNUGK_MAJOR_VERSION
# define GNUGK_MAJOR_VERSION 2
#endif

/* Minor version number of the gatekeeper */
#ifndef GNUGK_MINOR_VERSION
# define GNUGK_MINOR_VERSION 3
#endif

/* Release status for the gatekeeper */
#ifndef GNUGK_BUILD_TYPE
/* might be: AlphaCode, BetaCode, ReleaseCode */
# define GNUGK_BUILD_TYPE ReleaseCode
/* Set this Macro if Release Code */
#endif

/* Build number of the gatekeeper */
#ifndef GNUGK_BUILD_NUMBER
# define GNUGK_BUILD_NUMBER 0
#endif

#endif  /* GNUGK_VERSION_H */

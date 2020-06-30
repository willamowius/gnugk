//////////////////////////////////////////////////////////////////
//
// Version number for GnuGk
//
// Copyright (c) 2002, Dr.-Ing. Martin Froehlich <Martin.Froehlich@mediaWays.net>
// Copyright (c) 2006-2020, Jan Willamowius
//
// This work is published under the GNU Public License version 2 (GPLv2)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the OpenH323/H323Plus and OpenSSL library.
//
//////////////////////////////////////////////////////////////////

#ifndef GNUGK_VERSION_H
#define GNUGK_VERSION_H "@(#) $Id$"

/* Major version number of the gatekeeper */
#ifndef GNUGK_MAJOR_VERSION
# define GNUGK_MAJOR_VERSION 5
#endif

/* Minor version number of the gatekeeper */
#ifndef GNUGK_MINOR_VERSION
# define GNUGK_MINOR_VERSION 6
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

#endif	/* GNUGK_VERSION_H */

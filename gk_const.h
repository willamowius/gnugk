//////////////////////////////////////////////////////////////////
//
// gk_const.h	constants for gatekeeper ports etc.
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
//
// History:
// 	991002	initial version (Jan Willamowius)
//  990127  moved all to config file (towi)
//
//////////////////////////////////////////////////////////////////


#ifndef GK_CONST_H
#define GK_CONST_H

/* all values can be set in the config file, section [Gatekeeper::<InstanceName>]
 * these are just the defaults
 */

#define GK_DEF_UNICAST_RAS_PORT		1719
#define GK_DEF_MULTICAST_PORT		1718
#define GK_DEF_MULTICAST_GROUP		"224.0.1.41"

/* port used by gatekeeper for routed signaling: anything != 1720 so endpoint can be on same IP as GK */
#define GK_DEF_ROUTE_SIGNAL_PORT	1721

/* well known signal port */
#define GK_DEF_ENDPOINT_SIGNAL_PORT	1720

#define GK_DEF_STATUS_PORT			7000

#define GK_DEF_LISTEN_QUEUE_LENGTH		1024


#endif


//////////////////////////////////////////////////////////////////
//
// MySQL Connection for GNU Gatekeeper
//
// Copyright (c) Citron Network Inc. 2002-2003
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// initial author: Chih-Wei Huang <cwhuang@linux.org.tw>
// initial version: 07/15/2003
//
//////////////////////////////////////////////////////////////////

#ifndef MYSQLCON_H
#define MYSQLCON_H "@(#) $Id$"

#ifndef _PTLIB_H
#include <ptlib.h>
#endif


struct st_mysql;
struct st_mysql_res;
typedef st_mysql MYSQL;
typedef st_mysql_res MYSQL_RES;

class MySQLConnection {
public:
	class Result {
	public:
		Result(MYSQL_RES *r = 0) : m_result(r) {}
		~Result();

		operator MYSQL_RES *() { return m_result; }
		bool Exec(MYSQL *, const char *);
		bool Store(MYSQL *, const char *);

	private:
		MYSQL_RES *m_result;
	};

	MySQLConnection(PConfig *, const char *);
	virtual ~MySQLConnection();

	bool Query(const PString &, Result &);
	bool Query(const PString &, PStringArray &);
	bool Query(const PString &, PString &);

protected:
	PString GetSelectClause(const PString &) const;

	bool Init();
	void Cleanup();

	PMutex m_mutex;
	MYSQL *m_connection;
	PString m_clause;

	PConfig *m_config;
	const char *m_section;
};

#endif // MYSQLCON_H

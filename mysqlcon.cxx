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


#ifdef HAS_MYSQL
#ifndef __mysqlcon_h_
#include "mysqlcon.h"
#endif
#ifdef WIN32
#include <ptlib/socket.h>
#pragma comment(lib, "libmySQL.lib")
#endif
#include <mysql.h>

// class MySQLConnection::Result
MySQLConnection::Result::~Result()
{
	if (m_result)
		mysql_free_result(m_result);
}

bool MySQLConnection::Result::Exec(MYSQL *connection, const char *sqlcmd)
{
	if (mysql_query(connection, sqlcmd) == 0)
		return true;
	PTRACE(2, "MySQL\tExecute cmd '" << sqlcmd << "' failed") ;
	return false;
}

bool MySQLConnection::Result::Store(MYSQL *connection, const char *sqlcmd)
{
	if (!Exec(connection, sqlcmd))
		return false;
	m_result = mysql_store_result(connection);
	return mysql_num_rows(m_result) > 0;
}


// class MySQLConnection
MySQLConnection::MySQLConnection(PConfig *cfg, const char *section)
      : m_connection(0), m_config(cfg), m_section(section)
{
	Init();
}

MySQLConnection::~MySQLConnection()
{
	PWaitAndSignal lock(m_mutex);
	Cleanup();
}

bool MySQLConnection::Query(const PString & id, Result & result)
{
	PString sqlcmd = GetSelectClause(id);
	PWaitAndSignal lock(m_mutex);
	return (m_connection || Init()) && result.Store(m_connection, sqlcmd);
}

bool MySQLConnection::Query(const PString & id, PStringArray & result)
{
	Result mresult;
	if (!Query(id, mresult))
		return false;
	MYSQL_ROW row = mysql_fetch_row(mresult);
	result = PStringArray(mysql_num_fields(mresult), row);
	return true;
}

bool MySQLConnection::Query(const PString & id, PString & result)
{
	PStringArray aresult;
	if (!Query(id, aresult) || aresult.GetSize() == 0)
		return false;
	result = aresult[0];
	return true;
}

PString MySQLConnection::GetSelectClause(const PString & id) const
{
	return PString(PString::Printf, m_clause, (const char *)id);
}

bool MySQLConnection::Init()
{
	PStringArray host = m_config->GetString(m_section, "Host", "localhost").Tokenise(",:;", false);
	unsigned port = m_config->GetInteger(m_section, "Port", MYSQL_PORT);
	PString dbname = m_config->GetString(m_section, "Database", "mysql");
	PString user = m_config->GetString(m_section, "User", "");
	PString passwd = m_config->GetString(m_section, "Password", "");

	PString table = m_config->GetString(m_section, "Table", "");
	PString alias = m_config->GetString(m_section, "KeyField", "");
	PString query = m_config->GetString(m_section, "DataField", "");
	PString extra = m_config->GetString(m_section, "ExtraCriterion", "");

	PINDEX i = 0, s = host.GetSize();
	if ((m_connection = mysql_init(0))) {
		while (i < s) {
			if (mysql_real_connect(m_connection, host[i], user, passwd, dbname, port, 0, 0))
				break;
			PTRACE(1, "MySQL\tError: " << mysql_error(m_connection));
			++i;
		}
		if (i == s) {
			Cleanup();
			return false;
		}
	} else {
		PTRACE(1, "MySQL\tInit Error!");
		return false;
	}

	PTRACE(2, "MySQL\tConnect to server " << host[i] << ", database " << dbname);
	m_clause.sprintf(
		"select %s from %s where %s = '%%s'",
		(const char *)query,
		(const char *)table,
		(const char *)alias
	);
	if (!extra)
		m_clause += " and " + extra;

	PTRACE(1, "MySQL\tReady for query '" << m_clause << '\'');
	return true;
}

void MySQLConnection::Cleanup()
{
	mysql_close(m_connection);
	m_connection = 0;
}

#endif

/*
 * gkconfig.cxx
 *
 * Custom PConfig implementation that allows chaining together more
 * than one config source (file) and access them through a single config instance.
 *
 * Copyright (c) 2006-2018, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
*
 */

#include <ptlib.h>
#include "gkconfig.h"

GatekeeperConfig::GatekeeperConfig(
	const PFilePath & filename, /// Explicit name of the configuration file.
	const PString & section, /// Default section to search for variables.
	PConfig * chainedConfig /// a next config in the chain
	) : PConfig(filename, section), m_chainedConfig(chainedConfig)
{
}

GatekeeperConfig::~GatekeeperConfig()
{
	delete m_chainedConfig;
}

#ifdef hasPConfigArray
PStringArray GatekeeperConfig::GetSections() const
{
	PStringArray list = PConfig::GetSections();
#else
PStringList GatekeeperConfig::GetSections() const
{
	PStringList list = PConfig::GetSections();
#endif

	if (m_chainedConfig != NULL) {
		PStringList chainedList = m_chainedConfig->GetSections();
		for (PINDEX i = 0; i < chainedList.GetSize(); i++)
			if (list.GetValuesIndex(chainedList[i]) == P_MAX_INDEX)
				list.AppendString(chainedList[i]);
	}

	return list;
}

#ifdef hasPConfigArray
PStringArray GatekeeperConfig::GetKeys(const PString & theSection) const
{
	PStringArray list = PConfig::GetKeys(theSection);
#else
PStringList GatekeeperConfig::GetKeys(const PString & theSection) const
{
	PStringList list = PConfig::GetKeys(theSection);
#endif

	if (m_chainedConfig != NULL) {
		PStringList chainedList = m_chainedConfig->GetKeys(theSection);
		for (PINDEX i = 0; i < chainedList.GetSize(); i++)
			if (list.GetValuesIndex(chainedList[i]) == P_MAX_INDEX)
				list.AppendString(chainedList[i]);
	}

	return list;
}

void GatekeeperConfig::DeleteSection(const PString & theSection)
{
	PConfig::DeleteSection(theSection);
	if (m_chainedConfig != NULL)
		m_chainedConfig->DeleteSection(theSection);
}

void GatekeeperConfig::DeleteKey(const PString & theSection, const PString & theKey)
{
	PConfig::DeleteKey(theSection, theKey);
	if (m_chainedConfig != NULL)
		m_chainedConfig->DeleteKey(theSection, theKey);
}

PBoolean GatekeeperConfig::HasKey(const PString & theSection, const PString & theKey) const
{
	return PConfig::HasKey(theSection, theKey)
		|| (m_chainedConfig != NULL && m_chainedConfig->HasKey(theSection, theKey));
}

PStringToString GatekeeperConfig::GetAllKeyValues(const PString & section) const
{
	PStringToString dict = PConfig::GetAllKeyValues(section);

	if (m_chainedConfig != NULL) {
		const PStringList keys = m_chainedConfig->GetKeys(section);
		for (PINDEX i = 0; i < keys.GetSize(); i++)
			if (!dict.Contains(keys[i]))
				dict.SetAt(keys[i], m_chainedConfig->GetString(section, keys[i], ""));
	}

	return dict;
}

PString GatekeeperConfig::GetString(const PString & theSection,
	const PString & theKey, const PString & dflt
	) const
{
	if (m_chainedConfig == NULL || PConfig::HasKey(theSection, theKey))
		return PConfig::GetString(theSection, theKey, dflt);
	else
		return m_chainedConfig->GetString(theSection, theKey, dflt);
}

PBoolean GatekeeperConfig::GetBoolean(const PString & section, const PString & key, PBoolean dflt) const
{
	if (m_chainedConfig == NULL || PConfig::HasKey(section, key))
		return PConfig::GetBoolean(section, key, dflt);
	else
		return m_chainedConfig->GetBoolean(section, key, dflt);
}

long GatekeeperConfig::GetInteger(const PString & section, const PString & key, long dflt) const
{
	if (m_chainedConfig == NULL || PConfig::HasKey(section, key))
		return PConfig::GetInteger(section, key, dflt);
	else
		return m_chainedConfig->GetInteger(section, key, dflt);
}

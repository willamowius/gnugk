/*
 * gkconfig.h
 *
 * Custom PConfig implementation that allows chaining together more
 * than one config source (file) and access them through a single config instance.
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 * Copyright (c) 2006-2018, Jan Willamowius
 *
 * This work is published under the GNU Public License version 2 (GPLv2)
 * see file COPYING for details.
 * We also explicitly grant the right to link this code
 * with the OpenH323/H323Plus and OpenSSL library.
 *
 */

#ifndef GKCONFIG_H
#define GKCONFIG_H "@(#) $Id$"

#include "config.h"

class GatekeeperConfig : public PConfig
{
	PCLASSINFO(GatekeeperConfig, PConfig);

public:
	/** Create a new configuration object. */
	GatekeeperConfig(
		const PFilePath & filename, /// Explicit name of the configuration file.
		const PString & section, /// Default section to search for variables.
		PConfig * chainedConfig = NULL /// a next config in the chain
		);

	virtual ~GatekeeperConfig();

	/**@name Section functions */
	//@{
	/** Get all of the section names currently specified in the file. A section
	    is the part specified by the [ and ] characters.

	    Note when the #Environment# source is being used this will
	    return an empty list as there are no section present.

	    @return list of all section names.
	*/
#ifdef hasPConfigArray
    virtual PStringArray GetSections() const;
#else
    virtual PStringList GetSections() const;
#endif

	/** Get a list of all the keys in the section. */
#ifdef hasPConfigArray
	virtual PStringArray GetKeys(
#else
	virtual PStringList GetKeys(
#endif
		const PString & theSection /// Section to use instead of the default.
		) const;

	/** Get all of the keys in the section and their values.

	    @return Dictionary of all key names and their values.
	*/
	virtual PStringToString GetAllKeyValues(
		const PString & section /// Section to use instead of the default.
		) const;

    /** Delete all variables in the specified section.

	    Note that the section header is also removed so the section will not
	    appear in the GetSections() function.
	*/
	virtual void DeleteSection(
		const PString & theSection /// Name of section to delete.
		);

	/** Delete the particular variable in the specified section.

	    Note that the variable and key are removed from the file. The key will
	    no longer appear in the GetKeys() function. If you wish to delete the
	    value without deleting the key, use SetString() to set it to the empty
	    string.
	*/
	virtual void DeleteKey(
		const PString & theSection, /// Section to use instead of the default.
		const PString & theKey /// Key of the variable to delete.
    );

	/** Determine if the particular variable in the section is actually present.

	    This function allows a caller to distinguish between getting a saved
	    value or using the default value. For example if you called
	    GetString("MyKey", "DefVal") there is no way to distinguish between
	    the default "DefVal" being used, or the user had explicitly saved the
	    value "DefVal" into the PConfig.
	*/
	virtual PBoolean HasKey(
		const PString & theSection, /// Section to use instead of the default.
		const PString & theKey /// Key of the variable.
		) const;
	//@}

	/**@name Get/Set variables */
	//@{
	/** Get a string variable determined by the key in the section.

	    If the key is not present the value returned is the that provided by
	    the #dlft# parameter. Note that this is different from the
	    key being present but having no value, in which case an empty string is
	    returned.

	    @return string value of the variable.
	*/
	virtual PString GetString(
		const PString & theSection,  /// Section to use instead of the default.
		const PString & theKey,      /// The key name for the variable.
		const PString & dflt      /// Default value for the variable.
		) const;

	/** Get a boolean variable determined by the key in the section.

	    The boolean value can be specified in a number of ways. The TRUE value
	    is returned if the string value for the variable begins with either the
	    'T' character or the 'Y' character. Alternatively if the string can
	    be converted to a numeric value, a non-zero value will also return TRUE.
	    Thus the values can be Key=True, Key=Yes or Key=1 for TRUE and
	    Key=False, Key=No, or Key=0 for FALSE.

	    If the key is not present the value returned is the that provided by
	    the #dlft# parameter. Note that this is different from the
	    key being present but having no value, in which case FALSE is returned.

	    @return boolean value of the variable.
	*/
	virtual PBoolean GetBoolean(
		const PString & section, /// Section to use instead of the default.
		const PString & key, /// The key name for the variable.
		PBoolean dflt = FALSE /// Default value for the variable.
		) const;

	/** Get an integer variable determined by the key in the section. If the
	    section name is not specified then the default section is used.

	    If the key is not present the value returned is the that provided by
	    the #dlft# parameter. Note that this is different from the
	    key being present but having no value, in which case zero is returned.

	    @return integer value of the variable.
	*/
	virtual long GetInteger(
		const PString & section, /// Section to use instead of the default.
		const PString & key, /// The key name for the variable.
		long dflt = 0 /// Default value for the variable.
		) const;

private:
	/// a next config in the chain (or NULL if this is the last one)
	PConfig* m_chainedConfig;
};

#endif // GKCONFIG_H

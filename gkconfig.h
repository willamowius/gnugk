/*
 * gkconfig.h
 *
 * Custom PConfig implementation that allows chaining together more
 * than one config source (file) and access them through a single config instance.
 *
 * Copyright (c) 2004, Michal Zygmuntowicz
 *
 * This work is published under the GNU Public License (GPL)
 * see file COPYING for details.
 * We also explicitely grant the right to link this code
 * with the OpenH323 library.
 *
 * $Log$
 * Revision 1.6  2007/11/27 12:57:27  willamowius
 * preparation for PBoolean change in PWLib
 *
 * Revision 1.5  2007/09/13 11:17:11  willamowius
 * use same parameter name in declaration and implementation
 *
 * Revision 1.4  2006/04/14 13:56:19  willamowius
 * call failover code merged
 *
 * Revision 1.1.1.1  2005/11/21 20:20:00  willamowius
 *
 *
 * Revision 1.4  2005/11/15 19:52:56  jan
 * Michal v1 (works, but on in routed, not proxy mode)
 *
 * Revision 1.3  2005/02/11 17:23:04  zvision
 * Write SCCS keyword correctly
 *
 * Revision 1.2  2005/01/27 13:41:28  zvision
 * SQLConfig ported from 2.0 branch
 *
 * Revision 1.1.2.1  2004/06/28 00:16:20  zvision
 * All gatekeeper settings can be read from an SQL database
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
		const PFilePath& filename, /// Explicit name of the configuration file.
		const PString& section, /// Default section to search for variables.
		PConfig* chainedConfig = NULL /// a next config in the chain
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
    virtual PStringList GetSections() const;

	/** Get a list of all the keys in the section. */
	virtual PStringList GetKeys(
		const PString& theSection /// Section to use instead of the default.
		) const;

	/** Get all of the keys in the section and their values.

	    @return Dictionary of all key names and their values.
	*/
	virtual PStringToString GetAllKeyValues(
		const PString& section /// Section to use instead of the default.
		) const;

    /** Delete all variables in the specified section.

	    Note that the section header is also removed so the section will not
	    appear in the GetSections() function.
	*/
	virtual void DeleteSection(
		const PString& theSection /// Name of section to delete.
		);

	/** Delete the particular variable in the specified section.

	    Note that the variable and key are removed from the file. The key will
	    no longer appear in the GetKeys() function. If you wish to delete the
	    value without deleting the key, use SetString() to set it to the empty
	    string.
	*/
	virtual void DeleteKey(
		const PString& theSection, /// Section to use instead of the default.
		const PString& theKey /// Key of the variable to delete.
    );

	/** Determine if the particular variable in the section is actually present.

	    This function allows a caller to distinguish between getting a saved
	    value or using the default value. For example if you called
	    GetString("MyKey", "DefVal") there is no way to distinguish between
	    the default "DefVal" being used, or the user had explicitly saved the
	    value "DefVal" into the PConfig.
	*/
	virtual PBoolean HasKey(
		const PString& theSection, /// Section to use instead of the default.
		const PString& theKey /// Key of the variable.
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
		const PString& theSection,  /// Section to use instead of the default.
		const PString& theKey,      /// The key name for the variable.
		const PString& dflt      /// Default value for the variable.
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
		const PString& section, /// Section to use instead of the default.
		const PString& key, /// The key name for the variable.
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
		const PString& section, /// Section to use instead of the default.
		const PString& key, /// The key name for the variable.
		long dflt = 0 /// Default value for the variable.
		) const;

	/** Get a 64 bit integer variable determined by the key in the section.

	    If the key is not present the value returned is the that provided by
	    the #dlft# parameter. Note that this is different from the
	    key being present but having no value, in which case zero is returned.

	    @return integer value of the variable.
	*/
	virtual PInt64 GetInt64(
		const PString& section, /// Section to use instead of the default.
		const PString& key, /// The key name for the variable.
		PInt64 dflt = 0 /// Default value for the variable.
		) const;

	/** Get a floating point variable determined by the key in the section. If
	    the section name is not specified then the default section is used.

	    If the key is not present the value returned is the that provided by
	    the #dlft# parameter. Note that this is different from the
	    key being present but having no value, in which case zero is returned.

	    @return floating point value of the variable.
	*/
	virtual double GetReal(
		const PString &section, /// Section to use instead of the default.
		const PString &key, /// The key name for the variable.
		double dflt = 0 /// Default value for the variable.
		) const;

	/** Get a #PTime# variable determined by the key in the section. If
	    the section name is not specified then the default section is used.

	    If the key is not present the value returned is the that provided by
	    the #dlft# parameter. Note that this is different from the
	    key being present but having no value, in which case zero is returned.

	    @return time/date value of the variable.
	*/
	virtual PTime GetTime(
		const PString& section, /// Section to use instead of the default.
		const PString& key /// The key name for the variable.
		) const;
	/** Get a #PTime# variable determined by the key in the section. */
	virtual PTime GetTime(
		const PString& section, /// Section to use instead of the default.
		const PString& key, /// The key name for the variable.
		const PTime& dflt /// Default value for the variable.
		) const;
		
private:
	/// a next config in the chain (or NULL if this is the last one)
	PConfig* m_chainedConfig;
};

#endif // GKCONFIG_H

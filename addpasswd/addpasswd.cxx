//////////////////////////////////////////////////////////////////
//
// addpasswd.cxx
//
// $Id$
//
// Copyright (c) 2007-2014, Jan Willamowius
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitly grant the right to link this code
// with the PTLib library.
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <ptclib/cypher.h>
#include <ptlib/pprocess.h>

class Addpasswd : public PProcess
{
    PCLASSINFO(Addpasswd, PProcess)
    public:
        void Main();
};

PCREATE_PROCESS(Addpasswd)

PString Encrypt(const PString & key, const PString & password, int paddingByte)
{
	PTEACypher::Key encKey;
	memset(&encKey, paddingByte, sizeof(encKey));
	memcpy(&encKey, (const char*)key, min(sizeof(encKey), size_t(key.GetLength())));
	PTEACypher cypher(encKey);
	return cypher.Encode(password);
}

void Addpasswd::Main()
{
	PArgList args(GetArguments());
	if (args.GetCount() < 4) {
		cout << "Usage: addpasswd config-file section user password\n\n";
		return;
	}

	PConfig config(args[0], args[1]);
	if (config.GetSections().GetStringsIndex(args[1]) == P_MAX_INDEX) {
	    cerr << "Error: the specified config file does not contain a section named " << args[1] << endl;
	}

	int paddingByte = 0;
	const PString paddingByteKeyName("KeyFilled");

	if (config.HasKey(paddingByteKeyName)) {
		paddingByte = config.GetInteger(paddingByteKeyName, 0);
	} else {
	    if (config.HasKey("Gatekeeper::Main", paddingByteKeyName)) {
            paddingByte = config.GetInteger("Gatekeeper::Main", paddingByteKeyName, 0);
	    }
	}
	const PString key = args[2];
	const PString password = args[3];
	const PString encryptedPassword = Encrypt(key, password, paddingByte);
	cout << "Setting: " << key << "=" << encryptedPassword << endl;
	config.SetString(key, encryptedPassword);
}


// -*- mode: c++; eval: (c-set-style "linux"); -*-
//////////////////////////////////////////////////////////////////
//
// addpasswd.cxx
//
// - Automatic Version Information via CVS:
//   $Id$
//   $Source$
//
// This work is published under the GNU Public License (GPL)
// see file COPYING for details.
// We also explicitely grant the right to link this code
// with the OpenH323 library.
//
// History:
//      2001/09/27      initial version (Chih-Wei Huang)
//
//////////////////////////////////////////////////////////////////

#include <ptlib.h>
#include <ptclib/cypher.h>
#include "stl_supp.h"


class Client : public PProcess
{       
  PCLASSINFO(Client, PProcess)
  public:
    void Main();
};      


PCREATE_PROCESS(Client)

int keyFilled = 0;

PString Encrypt(const PString &key, const PString &clear)
{
	PTEACypher::Key thekey;
	memset(&thekey, keyFilled, sizeof(PTEACypher::Key));
	memcpy(&thekey, const_cast<PString &>(key).GetPointer(), min((long unsigned int)sizeof(PTEACypher::Key), static_cast<long unsigned int>(abs(key.GetLength()))));
	PTEACypher cypher(thekey);
	return cypher.Encode(clear);
}

PString Decrypt(const PString &key, const PString &encrypt)
{
	PTEACypher::Key thekey;
	memset(&thekey, keyFilled, sizeof(PTEACypher::Key));
	memcpy(&thekey, const_cast<PString &>(key).GetPointer(), min((long unsigned int)sizeof(PTEACypher::Key), static_cast<long unsigned int>(abs(key.GetLength()))));
	PTEACypher cypher(thekey);
	return cypher.Decode(encrypt);
}

void Client::Main()
{
	PArgList args(GetArguments());
	if (args.GetCount() < 4) {
		cout << "Usage: addpasswd config section userid password\n\n";
		return;
	}

	PConfig config(args[0], args[1]);
	keyFilled=(config.GetString("KeyFilled", "0")).AsInteger();
	PString userid = args[2], passwd = args[3];
	PString encrypt = Encrypt(userid, passwd);
	config.SetString(userid, encrypt);
}

// End of $Source$

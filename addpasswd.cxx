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

#ifndef lint
// mark object with version info in such a way that it is retrievable by
// the std. version/revision control tools like RCS/CVS ident cmd. At
// least the strings cmd will extract this info.
static const char gkid[] = GKGVS;
static const char vcid[] = "@(#) $Id$";
#endif /* lint */

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
	memcpy(&thekey, const_cast<PString &>(key).GetPointer(), min(sizeof(PTEACypher::Key), static_cast<unsigned int>(abs(key.GetLength()))));
	PTEACypher cypher(thekey);
	return cypher.Encode(clear);
}

PString Decrypt(const PString &key, const PString &encrypt)
{
	PTEACypher::Key thekey;
	memset(&thekey, keyFilled, sizeof(PTEACypher::Key));
	memcpy(&thekey, const_cast<PString &>(key).GetPointer(), min(sizeof(PTEACypher::Key), static_cast<unsigned int>(abs(key.GetLength()))));
	PTEACypher cypher(thekey);
	return cypher.Decode(encrypt);
}

void Client::Main()
{
	PArgList args(GetArguments());
	if (args.GetCount() < 3) {
		cout << vcid << "\n"
		     << "of " << GKGVS << "\n"
		     << "Usage: addpasswd config userid password\n\n";
		return;
	}

	PConfig config(args[0], "Password");
	keyFilled=(config.GetString("KeyFilled", "0")).AsInteger();
	PString userid = args[1], passwd = args[2];
	PString encrypt = Encrypt(userid, passwd);
	config.SetString(userid, encrypt);
}

// End of $Source$

// addpasswd.cxx

#include <algorithm>
#include <ptlib.h>
#include <ptclib/cypher.h>

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
	memcpy(&thekey, const_cast<PString &>(key).GetPointer(), min(sizeof(PTEACypher::Key), key.GetLength()));
	PTEACypher cypher(thekey);
	return cypher.Encode(clear);
}

PString Decrypt(const PString &key, const PString &encrypt)
{
	PTEACypher::Key thekey;
	memset(&thekey, keyFilled, sizeof(PTEACypher::Key));
	memcpy(&thekey, const_cast<PString &>(key).GetPointer(), min(sizeof(PTEACypher::Key), key.GetLength()));
	PTEACypher cypher(thekey);
	return cypher.Decode(encrypt);
}

void Client::Main()
{
	PArgList args(GetArguments());
	if (args.GetCount() < 3) {
		cout << "Usage: addpasswd config userid password\n\n";
		return;
	}

	PConfig config(args[0], "Password");
	keyFilled=(config.GetString("KeyFilled", "0")).AsInteger();
	PString userid = args[1], passwd = args[2];
	PString encrypt = Encrypt(userid, passwd);
	config.SetString(userid, encrypt);
}


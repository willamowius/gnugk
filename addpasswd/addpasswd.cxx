//////////////////////////////////////////////////////////////////
//
// addpasswd.cxx
//
// $Id$
//
// Copyright (c) 2007-2017, Jan Willamowius
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
#ifdef P_SSL
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#endif

class Addpasswd : public PProcess
{
    PCLASSINFO(Addpasswd, PProcess)
    public:
        void Main();
};

PCREATE_PROCESS(Addpasswd)

// need OpenSSL >= 1.0.x
#if defined(P_SSL) && OPENSSL_VERSION_NUMBER >= 0x1000000fL
PString PBKDF2_Digest(const PString & password)
{
    // the definitions here must match those in GkStatus.cxx
    const int iterations = 65536;
    const int outputBytes = 32;
    const unsigned saltSize = 8;

    unsigned char digest[outputBytes];
    char digestStr[2 * outputBytes + 1];
    memset(digestStr, 0, sizeof(digestStr));
    unsigned char salt[saltSize];
    char saltStr[2 * saltSize + 1];
    memset(saltStr, 0, sizeof(saltStr));

    // initialize random number generator
    if (!RAND_status()) {
#ifdef P_LINUX
        RAND_load_file("/dev/urandom", 1024);
#else
        BYTE seed[1024];
        for (size_t i = 0; i < sizeof(seed); i++)
            seed[i] = (BYTE)rand();
        RAND_seed(seed, sizeof(seed));
#endif
    }

    // get a random salt per password
    if (RAND_bytes(salt, saltSize) != 1) {
        cout << "Error: RAND_bytes() failed" << endl;
        exit(1);
    }
    for (unsigned i = 0; i < saltSize; i++)
        sprintf(saltStr + (i * 2), "%02x", 255 & salt[i]);

    PKCS5_PBKDF2_HMAC((const char*)password, password.GetLength(), (const unsigned char*)saltStr, 2*saltSize, iterations, EVP_sha512(), outputBytes, digest);
    for (unsigned i = 0; i < sizeof(digest); i++)
        sprintf(digestStr + (i * 2), "%02x", 255 & digest[i]);

    return PString("PBKDF2:") + saltStr + "-" + digestStr;
}
#endif // P_SSL

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

    const PString filename = args[0];
    const PString section = args[1];
	const PString key = args[2];
	const PString password = args[3];
	PConfig config(filename, section);
	PString encryptedPassword;

#if defined(P_SSL) && OPENSSL_VERSION_NUMBER >= 0x1000000fL
    if (section == "GkStatus::Auth") {
        encryptedPassword = PBKDF2_Digest(password);
    }
    else
#endif // P_SSL
    {
        // traditional password obfuscation
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
        encryptedPassword = Encrypt(key, password, paddingByte);
    }
	cout << "Setting: " << key << "=" << encryptedPassword << endl;
	config.SetString(key, encryptedPassword);
}


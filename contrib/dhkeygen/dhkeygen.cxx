 /*
 *
 * dhkeygen.cxx
 *
 * Copyright (c) 2015 Spranto International Pte Ltd. All Rights Reserved.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at http://mozilla.org/MPL/2.0/
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * Contributor(s): ______________________________________.
 *
 * $Id$
 * 
 */

#include <ptlib.h>
#include <ptlib/pprocess.h>
#include <ptclib/cypher.h>


#ifndef P_SSL
    #if _WIN32
    #pragma error("OpenSSL support required in PTLIB to compile this program")
    #else
    #error("OpenSSL support required in PTLIB to compile this program")
    #endif
#endif

extern "C" {
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
};

const char * const OID_DH512  = "0.0.8.235.0.3.40";
const char * const OID_DH1024 = "0.0.8.235.0.3.43";
const char * const OID_DH1536 = "0.0.8.235.0.3.44";
const char * const OID_DH2048 = "0.0.8.235.0.3.45";
const char * const OID_DH4096 = "0.0.8.235.0.3.47";
const char * const OID_DH6144 = "0.0.8.235.0.4.77";
const char * const OID_DH8192 = "0.0.8.235.0.4.78";


const static struct {
    const char * parameterOID;
    unsigned     sz;
} DHParameters[] = {
     { OID_DH8192,  8192 },
     { OID_DH6144,  6144 },
     { OID_DH4096,  4096 },
     { OID_DH2048,  2048 },
     { OID_DH1536,  1536 },
     { OID_DH1024,  1024 },
     { OID_DH512,    512 }
};

class DHProcess : public PProcess
{
  PCLASSINFO(DHProcess, PProcess)
  public:
    DHProcess()
      : PProcess("H323Plus", "dhkeygen", 1, 0, ReleaseCode, 1)
    { }
    void Main();
};

PCREATE_PROCESS(DHProcess)

PBoolean DH_Save(DH * dh, const PFilePath & dhFile, const PString & oid)
{
  PConfig config(dhFile, oid);
  PString str = PString();
  int len = BN_num_bytes(dh->p);
  unsigned char * data = (unsigned char *)OPENSSL_malloc(len); 

  if (data != NULL && BN_bn2bin(dh->p, data) > 0) {
    str = PBase64::Encode(data, len, "");
    config.SetString("PRIME",str);
  }
  OPENSSL_free(data);

  data = (unsigned char *)OPENSSL_malloc(len); 
  if (data != NULL && BN_bn2bin(dh->g, data) > 0) {
    str = PBase64::Encode(data, len, "");
    config.SetString("GENERATOR",str);
  }
  OPENSSL_free(data);

  return true;
}

PBoolean DH_ExportPEM(DH * dh, const PFilePath & dhFile)
{
  bool success = true;
  
  BIO * out = BIO_new(BIO_s_file());
  if (BIO_write_filename(out,(char *)(const char *)dhFile) <= 0)
    success = false;

  if (success && !PEM_write_bio_DHparams(out,dh))
	success = false;

  BIO_free_all(out);
  return success;
}

void DHProcess::Main()
{
  cout << "H.323 Diffie-Hellman KeyPair Generator" << endl;

  PArgList & args = GetArguments(); 
  cout << args << endl;
  args.Parse(
          "h-help."
          "l-length:"
          "g-generator:"
          "-oid"
          "f-file:"
          "p-pem."
#if PTRACING
          "o-output:"
          "t-trace."
#endif
          );

  if (args.HasOption('h') || !args.HasOption('l') || !args.HasOption('g')) {
    cout << "Usage : " << GetName() << " -l <keylength> -g <generator> -f <filename>\n"
            "Options:\n"
            "   l-length:        : Keylength 512 1024 1536 2048 4096 6144 8192\n"
            "   g-generator:     : Generator Must be one of 2 or 5\n"
            "   -oid             : Parameter OID (only if custom)\n"
            "   f-file:          : Filename to store key file\n"
            "   p-pem.           : Export to PEM encoded file (TLS parameters)\n"
#if PTRACING
            "   o-output:        : Trace log output file\n"
            "   t-trace.         : Trace log level\n"
#endif
            "   h-help.          : Help text\n";
      return;
  }

#if PTRACING
  PTrace::Initialise(args.GetOptionCount('t'),
                     args.HasOption('o') ? (const char *)args.GetOptionString('o') : NULL,
         PTrace::Blocks | PTrace::Timestamp | PTrace::Thread | PTrace::FileAndLine);
#endif

  PFilePath exportPath = "dhkey.ini";
  PString keyOID;
  PINDEX  keyLength=0;
  PINDEX  keyGenerator=0;

    if (args.HasOption('f'))
        exportPath = args.GetOptionString('f');
  

    unsigned inputGen = (unsigned)args.GetOptionString('g').AsInteger();
    if (inputGen == 2 || inputGen == 5) {
        keyGenerator = inputGen;
    } else {
        cout << "Unknown Generator: " << inputGen << " must be one of: 2,5\n";
        return;
    }

    unsigned inputLength = (unsigned)args.GetOptionString('l').AsInteger();
    if (!args.HasOption('p')) {
        if (args.HasOption("oid")) {
           keyOID = args.GetOptionString("oid"); 
           keyLength = inputLength;
        } else {
            for (PINDEX i = 0; i < PARRAYSIZE(DHParameters); ++i) {
                if (DHParameters[i].sz == inputLength) {
                    keyOID = DHParameters[i].parameterOID;
                    keyLength = inputLength;
                    break;
                }
            }
        }
    }

    if (!keyLength) {
        cout << "Unknown Key Length: " << inputLength << " must be one of: 512,1024,1536,2048,4096,6144,8192\n";
        return;
    }

    cout << "Generating Keypair length " << keyLength << " generator " << keyGenerator << "\n" << "This may take a few minutes!\n";

   DH *dh = DH_new();
   if (!DH_generate_parameters_ex(dh, keyLength, keyGenerator, NULL)) {
        cout << "Error generating Key Pair\n";
        DH_free(dh);
        dh = NULL;
        return;
   }
   cout << "Keypair Generated. Checking for safe prime.\n";

  int i=0;
  if (!DH_check(dh, &i)) {
    switch (i) {
     case DH_CHECK_P_NOT_PRIME:
         cout << " Error: p value is not prime\n";
         break;
     case DH_CHECK_P_NOT_SAFE_PRIME:
         cout << " Error: p value is not a safe prime\n";
         break;
     case DH_UNABLE_TO_CHECK_GENERATOR:
         cout << " Error: unable to check the generator value\n";
         break;
     case DH_NOT_SUITABLE_GENERATOR:
         cout << " Error: the g value is not a generator\n";
         break;
    }
    DH_free(dh);
    dh = NULL;
    return;
  }

  cout << "Exporting Keypair...\n";

  PBoolean success = false;
  if (args.HasOption('p'))
      success = DH_ExportPEM(dh,exportPath);
  else 
      success = DH_Save(dh,exportPath,keyOID);

  if (!success)
      cout << "Error exporting keyPair!" << endl;
  else
      cout << "KeyPair successfully created!" << endl;

  DH_free(dh);
  dh = NULL;

}


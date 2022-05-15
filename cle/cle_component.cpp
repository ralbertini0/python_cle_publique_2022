//#include <pybind11/pybind11.h>
#include "micro-ecc/uECC.h"
char version[]="1.0";

char const* getVersion() {
	return version;
}

uint8_t hexchr2bin(const char hex)
{
	uint8_t result;

	if (hex >= '0' && hex <= '9') {
		result = hex - '0';
	} else if (hex >= 'A' && hex <= 'F') {
		result = hex - 'A' + 10;
	} else if (hex >= 'a' && hex <= 'f') {
		result = hex - 'a' + 10;
	} else {
		return 0;
	}
	return result;
}



void hexStringToBin(uint8_t *out,const char * hexPrivate) {
    for (int i=0; i<32; i++){
	out[i] = hexchr2bin(hexPrivate[2*i])<<4 | hexchr2bin(hexPrivate[2*i+1]);
    }
}


char *binToHexString(char *out,const unsigned char *bin, size_t len)
{
    size_t  i;

    if (bin == NULL || len == 0)
	return NULL;

    for (i=0; i<len; i++) {

	out[i*2]   = "0123456789abcdef"[bin[i] >> 4];
	out[i*2+1] = "0123456789abcdef"[bin[i] & 0x0F];
    }
    out[len*2] = '\0';

    return out;
}






class Cle
{
    public:
        Cle(){}
        ~Cle() {}

        void initialize(std::string &nb) { 
		PrivateKey=nb;
		uint8_t binaryPrivate[32];
		hexStringToBin(binaryPrivate,PrivateKey.c_str());
		const int publicKeySize=uECC_curve_public_key_size(uECC_secp256k1());
		uint8_t *varIntPublicKey = new uint8_t[publicKeySize];
		uECC_compute_public_key(binaryPrivate,varIntPublicKey,uECC_secp256k1());
		char hexPublicKey[128];
		binToHexString(hexPublicKey,varIntPublicKey,64);
		PublicKey=std::string(hexPublicKey,128);
		//PublicKey=std::string( varIntPublicKey, varIntPublicKey+publicKeySize );
		}
		
        const std::string &getPrivateKey() const { return PrivateKey; }
		const std::string &getPublicKey() const { return PublicKey; }

    private:
        std::string PublicKey;
        std::string PrivateKey;
};
 
namespace py = pybind11;


PYBIND11_MODULE(cle_component,greetings)
{
  greetings.doc() = "greeting_object 1.0";
  greetings.def("getVersion", &getVersion, "a function returning the version");
  
   // bindings to Cle class
    py::class_<Cle>(greetings, "Cle", py::dynamic_attr())
        .def(py::init())
        .def("initialize", &Cle::initialize)
        .def("getPrivateKey", &Cle::getPrivateKey)
        .def("getPublicKey", &Cle::getPublicKey);
}

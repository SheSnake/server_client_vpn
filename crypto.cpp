
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <iostream>
#include <string.h>
using namespace std;


void AES_Encrypt(unsigned char* in, unsigned char* out,
		size_t len, const AES_KEY* key,
		unsigned char* ivec) {
	size_t n = 0;
	const unsigned char* iv = ivec;
	if(len == 0) return;
	while(len) {
		for(n = 0; n < 16 && n < len; ++n) {
			out[n] = in[n] ^ iv[n];
		}
		for(; n < 16; ++n) {
			out[n] = iv[n];
		}
		AES_encrypt(out, out, key);
		iv = out;
		if(len <= 16)
			break;
		len -= 16;
		in += 16;
		out += 16;
	}
	memcpy(ivec, iv, 16);	
}

void AES_Decrypt(unsigned char* in, unsigned char* out,
		size_t len, const AES_KEY* key,
		unsigned char* ivec) {
	size_t n;
	union {
		size_t t[16 / sizeof(size_t)];
		unsigned char c[16];
	} tmp;

	if (len == 0)
		return;

	while (len) {
		unsigned char c;
		AES_decrypt(in, tmp.c, key);
		for (n = 0; n < 16 && n < len; ++n) {
			c = in[n];
			out[n] = tmp.c[n] ^ ivec[n];
			ivec[n] = c;
		}
		if (len <= 16) {
			for (; n < 16; ++n)
				ivec[n] = in[n];
			break;
		}
		len -= 16;
		in += 16;
		out += 16;
	}
}


std::string EncodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )  {  
	if (strPemFileName.empty() || strData.empty())  {  
		return "";  
	}  
	FILE* hPubKeyFile = fopen(strPemFileName.c_str(), "rb");  
	if( hPubKeyFile == NULL )  {  
		return "";   
	}  
	std::string strRet;  
	RSA* pRSAPublicKey = RSA_new();  
	if(PEM_read_RSA_PUBKEY(hPubKeyFile, &pRSAPublicKey, 0, 0) == NULL)  {  
		return "";  
	}  

	int nLen = RSA_size(pRSAPublicKey);  
	char* pEncode = new char[nLen + 1];  
	int ret = RSA_public_encrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pEncode, pRSAPublicKey, RSA_PKCS1_PADDING);  
	if (ret >= 0)  {  
		strRet = std::string(pEncode, ret);  
	}  
	delete[] pEncode;  
	RSA_free(pRSAPublicKey);  
	fclose(hPubKeyFile);  
	CRYPTO_cleanup_all_ex_data();   
	return strRet;  
}  
  
//解密  
std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData )  {  
	if (strPemFileName.empty() || strData.empty())  {  
		return "";  
	}  
	FILE* hPriKeyFile = fopen(strPemFileName.c_str(),"rb");  
	if( hPriKeyFile == NULL )  {  
		return "";  
	}  
	std::string strRet;  
	RSA* pRSAPriKey = RSA_new();  
	if(PEM_read_RSAPrivateKey(hPriKeyFile, &pRSAPriKey, 0, 0) == NULL)  {  
		return "";  
	}  
	int nLen = RSA_size(pRSAPriKey);  
	char* pDecode = new char[nLen+1];    
	int ret = RSA_private_decrypt(strData.length(), (const unsigned char*)strData.c_str(), (unsigned char*)pDecode, pRSAPriKey, RSA_PKCS1_PADDING);  
	if(ret >= 0)  {  
		strRet = std::string((char*)pDecode, ret);  
	}  
	delete [] pDecode;  
	RSA_free(pRSAPriKey);  
	fclose(hPriKeyFile);  
	CRYPTO_cleanup_all_ex_data();   
	return strRet;  
}  

char* generatePriKey(int len) {
	srand(time(NULL));
	string letters = "qwertyuiopasdfghjklmnbvcxz123567890-=.+";
	int num = letters.length();
	char *key = new char[len+1];
	key[len] = 0;
	for(int i = 0; i < len; ++i) {
		int index = rand() % num;	
		key[i] = letters[index];
	}
	return key;
}

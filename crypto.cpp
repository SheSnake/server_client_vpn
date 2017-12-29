
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <string.h>
#include "4over6_util.h"
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


int mai(int argc , char** argv) {
	if(argc != 2) {
	    printf("使用方法为：\n./cbc text\ntext为待加密的明文。\n");
		return -1;
	}

	unsigned char *data = (unsigned char*)argv[1];
	printf("原始数据：%s\n",data);
	size_t len = strlen(argv[1]);
	printf("明文长度：%ld\n",len);

	size_t length = ((len+AES_BLOCK_SIZE-1)/AES_BLOCK_SIZE)*AES_BLOCK_SIZE;  //对齐分组

	unsigned char userkey[AES_BLOCK_SIZE];
	unsigned char *iv1 = new unsigned char[AES_BLOCK_SIZE];
	unsigned char *iv2 = new unsigned char[AES_BLOCK_SIZE];
	unsigned char *encrypt_result = new unsigned char[length];
	unsigned char *decrypt_result = new unsigned char[length];


	string two = EncodeRSAKeyFile("pubkey.pem", argv[1]);  
    cout << "public encrypt: " << two << endl;  
	  
	string three = DecodeRSAKeyFile("prikey.pem", two);  
	cout << "private decrypt: " << three << endl;  

	AES_KEY en_key;
	AES_KEY de_key;
	
	memset(userkey,'k',AES_BLOCK_SIZE);
	
	memset((unsigned char*)iv1,'m',AES_BLOCK_SIZE);
	memset((unsigned char*)iv2,'m',AES_BLOCK_SIZE);
	
	memset((unsigned char*)encrypt_result, 0, length);
	memset((unsigned char*)decrypt_result, 0, length);

	AES_set_encrypt_key(userkey, AES_BLOCK_SIZE*8, &en_key);
	AES_set_decrypt_key(userkey, AES_BLOCK_SIZE*8, &de_key);
	
	
	printf("加密密钥：%d \n",en_key);
	AES_Encrypt(data, encrypt_result, len, &en_key, iv1);
	printf("加密结果：%slen:  \n",encrypt_result);

	printf("解密密钥：%d \n",de_key);
	AES_Decrypt(encrypt_result, decrypt_result, len, &de_key, iv2);
	int i = 0;
	for(;;++i)
		if(decrypt_result[i] == '\0')break;
	printf("解密结果：%s len:%d \n",decrypt_result, i);




	return 0;
}

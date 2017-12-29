
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/pem.h>
#include <iostream>


void AES_Encrypt(unsigned char* in, unsigned char* out, size_t len, const AES_KEY* key, unsigned char* ivec);

void AES_Decrypt(unsigned char* in, unsigned char* out,	size_t len, const AES_KEY* key, unsigned char* ivec);

std::string EncodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData );

std::string DecodeRSAKeyFile( const std::string& strPemFileName, const std::string& strData );

char* generatePriKey(int len);

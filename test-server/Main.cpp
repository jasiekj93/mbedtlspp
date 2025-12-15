/**
 * @file Main.cpp
 * @author Adrian Szczepanski
 * @date 2025-12-04
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <cstdarg>
#include <cstring>

#include <errno.h>
#include <unistd.h>

#include <mbedtls/ssl_ciphersuites.h>
#include <mbedtls/debug.h>

#include <mbedtlspp/Ssl.hpp>

#include "SocketBio.hpp"

using namespace mbedtlspp;

std::string readFile(const std::string& filename) 
{
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content = buffer.str();
    
    return content;
}

int main(int argc, char* argv[])
{
    SocketBio bio("/tmp/mbedtls-test.sock", true);
    Configuration configuration(MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    Entropy entropy;
    drbg::Hmac drbg(entropy);
    
    static std::string serverCertData = readFile("test-server/server-cert.pem");
    
    // For PEM parsing, mbedTLS expects null-terminated data WITH the null terminator in size
    // c_str() is null-terminated, but length() doesn't include it, so add 1
    auto serverCert = x509::Crt::parse({ reinterpret_cast<const unsigned char*>(serverCertData.c_str()), serverCertData.length() + 1 });
    
    static std::string serverKeyData = readFile("test-server/server-key.pem");
    
    // For PEM parsing, mbedTLS expects null-terminated data WITH the null terminator in size
    auto serverKey = PrivateKey::parse({ reinterpret_cast<const unsigned char*>(serverKeyData.c_str()), serverKeyData.length() + 1 });

    if (not serverCert)
        throw std::runtime_error("Failed to parse server certificate");
    
    if (not serverKey)
        throw std::runtime_error("Failed to parse server private key");
    
    etl::vector<int, 2> ciphersuites = { MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384, 0 };
    configuration.setCiphersuites(ciphersuites);

    
    configuration.setOwnCert(serverCert.value(), serverKey.value());
    configuration.setRng(drbg);

    Ssl ssl(configuration, bio);
    int ret = 0;

    // Wait for TLS handshake
    std::cout << "Waiting for TLS handshake over Unix socket..." << std::endl;

    while ((ret = ssl.handshake()) != 0) 
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) 
        {
            throw std::runtime_error("TLS handshake failed with error: " + std::to_string(ret));
        }

        usleep(1000);
    }
    
    std::cout << "TLS handshake completed!" << std::endl;
    
    // Handle encrypted communication
    unsigned char buffer[256];
    while (1) 
    {
        ret = ssl.read({ buffer, sizeof(buffer) - 1 });
        
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) 
        {
            usleep(1000);
            continue;
        }
        
        if (ret <= 0) 
        {
            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) 
                std::cout << "Client disconnected" << std::endl;

            break;
        }
        
        buffer[ret] = '\0';
        std::cout << "Received: " << buffer << std::endl;
        
        // Echo response
        const char *response = "Message received over TLS/Unix socket";
        ssl.write({ (unsigned char *)response, strlen(response) });
    }
    
    ssl.closeNotify();
    std::cout << "TLS Connection closed." << std::endl;
	return ret;
}

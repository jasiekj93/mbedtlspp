/**
 * @file Main.cpp
 * @author Adrian Szczepanski
 * @date 2025-12-04
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include <mbedtlspp/Ssl.hpp>
#include <mbedtls/ssl_ciphersuites.h>

#include "SocketBio.hpp"

using namespace mbedtlspp;

// Function to read file contents
std::string readFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filename);
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}


int main(int argc, char* argv[])
{
    SocketBio bio("/tmp/mbedtls-test.sock", false);
    Configuration configuration(MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    Entropy entropy;
    drbg::Hmac drbg(entropy);

    static std::string caCertData = readFile("test-client/ca-cert.pem");
    
    auto cacert = x509::Crt::parse({ reinterpret_cast<const unsigned char*>(caCertData.c_str()), caCertData.length() + 1 });

    if(not cacert)
        throw std::runtime_error("Failed to parse CA certificates");
    
    // static const int ciphersuites[] = {
    //     MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
    //     0 // terminator
    // };

    etl::vector<int, 2> ciphersuites = { MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384, 0 };
    configuration.setCiphersuites(ciphersuites);
    
    configuration.setAuthMode(MBEDTLS_SSL_VERIFY_REQUIRED);
    configuration.setCaChain(cacert.value());
    configuration.setRng(drbg);    

    Ssl ssl(configuration, bio);
    int ret = 0;
    
    std::cout << "Starting TLS handshake over Unix socket..." << std::endl;

    while ((ret = ssl.handshake()) != 0) 
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) 
        {
            std::cout << "TLS handshake failed with error: " << ret << " (0x" << std::hex << -ret << std::dec << ")" << std::endl;
            throw std::runtime_error("TLS handshake failed with error: " + std::to_string(ret));
        }

        usleep(1000);
    }
    
    std::cout << "TLS handshake completed successfully!" << std::endl;
    
    // Send encrypted data
    const char *message = "Hello from TLS over Unix socket!";
    ret = ssl.write({ (unsigned char *)message, strlen(message) });

    if (ret > 0) 
        std::cout << "Sent: " << message << std::endl;
    
    // Read encrypted response
    unsigned char buffer[256];
    ret = ssl.read({ buffer, sizeof(buffer) - 1 });

    if (ret > 0) 
    {
        buffer[ret] = '\0';
        std::cout << "Received: " << buffer << std::endl;
    }
    
    ssl.closeNotify();
    std::cout << "TLS Connection closed." << std::endl;
    return ret;
}

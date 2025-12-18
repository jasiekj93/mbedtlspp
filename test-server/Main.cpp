/**
 * @file Main.cpp
 * @author Adrian Szczepanski
 * @date 2025-12-04
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>

#include <unistd.h>

#include <libeasytls/Server.hpp>

#include "SocketBio.hpp"
#include "CoutDebug.hpp"

using namespace easytls;

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

void doHandshake(Server& ssl)
{
    int ret = 0;

    std::cout << "Waiting for TLS handshake over Unix socket..." << std::endl;

    while ((ret = ssl.handshake()) != 0) 
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ and ret != MBEDTLS_ERR_SSL_WANT_WRITE) 
            throw std::runtime_error("TLS handshake failed with error: " + std::to_string(ret));

        usleep(1000);
    }
    std::cout << "TLS handshake completed!" << std::endl;
}

int receiveData(Server& ssl)
{
    int ret = 0;
    unsigned char buffer[256];
    while (true) 
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
        
        const char *response = "Message received over TLS/Unix socket";
        ssl.write({ (unsigned char *)response, strlen(response) });
    }

    return ret;
}


int main(int argc, char* argv[])
{
    SocketBio bio("/tmp/mbedtls-test.sock", true);
    auto debug = std::make_shared<CoutDebug>();
    Debug::setGlobal(debug);
    
    auto serverCertData = readFile("test-server/server-cert.pem");
    auto serverCert = x509::Certificate::parse({ reinterpret_cast<const unsigned char*>(serverCertData.c_str()), serverCertData.length() + 1 });
    
    auto serverKeyData = readFile("test-server/server-key.pem");
    auto serverKey = PrivateKey::parse({ reinterpret_cast<const unsigned char*>(serverKeyData.c_str()), serverKeyData.length() + 1 });

    if (not serverCert)
        throw std::runtime_error("Failed to parse server certificate. Status: " + std::to_string(x509::Certificate::getParseStatus()));
    
    if (not serverKey)
        throw std::runtime_error("Failed to parse server private key. Status: " + std::to_string(PrivateKey::getParseStatus()));
    
    auto tls = Server::tryCreate(bio, "server", serverCert.value(), serverKey.value());

    if(not tls)
        throw std::runtime_error("Failed to create TLS server. Result: " + std::to_string(Server::getCreateResult()));

    // auto& ssl = tls.value();
    Server ssl(bio, "server", serverCert.value(), serverKey.value());
    ssl.setDebug(Tls::DebugLevel::DEBUG);

    doHandshake(ssl);
    auto ret = receiveData(ssl);  

    if(ret != MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        ssl.closeNotify();

    std::cout << "TLS Connection closed." << std::endl;
	return ret;
}

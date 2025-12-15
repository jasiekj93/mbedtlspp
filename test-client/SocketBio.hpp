#pragma once

/**
 * @file SocketBio.hpp
 * @author Adrian Szczepanski
 * @date 12-12-2025
 */

#include <mbedtlspp/Bio.hpp>

class SocketBio : public mbedtlspp::Bio
{
public:
    SocketBio(const std::string& path, bool isServer);
    ~SocketBio(); 
    
    int read(etl::span<unsigned char> buffer) override;
    int read(etl::span<unsigned char> buffer, unsigned timeout) override;
    int write(etl::span<const unsigned char> buffer) override;

private:
    int socket_fd;
    std::string name;    
};
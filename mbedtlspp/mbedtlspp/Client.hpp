#pragma once

#include <mbedtlspp/Tls.hpp>

namespace mbedtlspp
{
    class Client : public Tls
    {
    public:
        static const etl::vector<int, 2> DEFAULT_CIPHERSUITE;  

        Client(Bio&, x509::Crt&, const Ciphersuites& = DEFAULT_CIPHERSUITE);

        using Tls::handshake;
        using Tls::closeNotify;

        using Tls::read;
        using Tls::write;

    private:
        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;

        Entropy entropy;
        drbg::Hmac drbg;
        Configuration configuration;
    };
}
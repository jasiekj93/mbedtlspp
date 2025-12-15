#pragma once

#include <mbedtlspp/Tls.hpp>

namespace mbedtlspp
{
    class Server : public Tls
    {
    public:
        static const etl::vector<int, 2> DEFAULT_CIPHERSUITE;  

        Server(Bio&, x509::Crt&, PrivateKey&, const Ciphersuites& = DEFAULT_CIPHERSUITE);

        using Tls::handshake;
        using Tls::closeNotify;

        using Tls::read;
        using Tls::write;

    private:
        Server(const Server&) = delete;
        Server& operator=(const Server&) = delete;

        Entropy entropy;
        drbg::Hmac drbg;
        Configuration configuration;
    };
}
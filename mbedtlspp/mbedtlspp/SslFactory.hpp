#pragma once

/**
 * @file SslFactory.hpp
 * @author Adrian Szczepanski
 * @date 15-12-2025
 */

#include <mbedtlspp/Ssl.hpp>

namespace mbedtlspp
{
    class SslFactory
    {
    public:
        static const etl::vector<int, 2> DEFAULT_CIPHERSUITE;  

        static Ssl createClient(Bio&, x509::Crt&, const Ciphersuites& = DEFAULT_CIPHERSUITE);
        static Ssl createServer(Bio&, x509::Crt&, PrivateKey&, const Ciphersuites& = DEFAULT_CIPHERSUITE);
    };
}
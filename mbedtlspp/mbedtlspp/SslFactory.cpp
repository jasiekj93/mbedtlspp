#include "SslFactory.hpp"

using namespace mbedtlspp;

const etl::vector<int, 2> SslFactory::DEFAULT_CIPHERSUITE = { MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384, 0 }; 

Ssl SslFactory::createClient(Bio& bio, x509::Crt& certificate, const Ciphersuites& ciphersuites)
{
    Configuration configuration(MBEDTLS_SSL_IS_CLIENT,
                                MBEDTLS_SSL_TRANSPORT_STREAM,
                                MBEDTLS_SSL_PRESET_DEFAULT);
    Entropy entropy;
    drbg::Hmac drbg(entropy);

    configuration.setCiphersuites(ciphersuites);
    configuration.setAuthMode(MBEDTLS_SSL_VERIFY_NONE);
    configuration.setRng(drbg); 

    return std::move(Ssl(configuration, bio));
}
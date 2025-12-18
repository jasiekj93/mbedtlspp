#include "Client.hpp"
#include "Psa.hpp"

using namespace easytls;

int Client::createResult = 0;

etl::optional<Client> easytls::Client::tryCreate(Bio& bio, etl::string_view hostname, x509::Certificate& certificate)
{
    if(not Psa::isInitialized())
        Psa::init();
    
    if(not Psa::isInitialized())
    {
        createResult = Psa::getInitResult();
        return etl::nullopt;
    }

    Client client(bio, hostname, certificate);

    if(createResult == 0)
        return etl::optional<Client>(etl::move(client));
    else
        return etl::nullopt;
}

Client::Client(Bio &bio, etl::string_view hostname, x509::Certificate &certificate)
    : Tls(bio, hostname)
{
    createResult = mbedtls_ssl_config_defaults(&config, 
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT);
                    
    if(createResult != 0)
        return;

    mbedtls_ssl_conf_ca_chain(&config, &certificate(), nullptr);
    mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
    createResult = mbedtls_ssl_setup(&ssl, &config);
}

#include "Server.hpp"
#include "Psa.hpp"

using namespace easytls;

int Server::createResult = 0;

etl::optional<Server> easytls::Server::tryCreate(Bio& bio, etl::string_view hostname, x509::Certificate& certificate, PrivateKey& privateKey)
{
    if(not Psa::isInitialized())
        Psa::init();
    
    if(not Psa::isInitialized())
    {
        createResult = Psa::getInitResult();
        return etl::nullopt;
    }

    Server server(bio, hostname, certificate, privateKey);

    if(createResult == 0)
        return etl::optional<Server>(etl::move(server));
    else
        return etl::nullopt;
}

Server::Server(Bio &bio, etl::string_view hostname, x509::Certificate &certificate, PrivateKey &privateKey)
    : Tls(bio, hostname)
{
    createResult = mbedtls_ssl_config_defaults(&config, 
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT);
    
    if(createResult != 0)
        return;

    mbedtls_ssl_conf_own_cert(&config, &certificate(), &privateKey());
    createResult = mbedtls_ssl_setup(&ssl, &config);
}
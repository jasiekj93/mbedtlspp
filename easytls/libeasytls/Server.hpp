#pragma once

/**
 * @file Server.hpp
 * @author Adrian Szczepanski
 * @date 18-12-2025
 */

#include <etl/optional.h>

#include <libeasytls/Tls.hpp>
#include <libeasytls/x509/Certificate.hpp>
#include <libeasytls/PrivateKey.hpp>

namespace easytls
{
    class Server : public Tls
    {
    public:
        Server(Bio&, etl::string_view hostname, x509::Certificate&, PrivateKey&);

        using Tls::handshake;
        using Tls::closeNotify;

        using Tls::read;
        using Tls::write;

        using Tls::setDebug;
    };
}
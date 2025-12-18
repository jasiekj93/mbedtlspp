#pragma once

/**
 * @file Client.hpp
 * @author Adrian Szczepanski
 * @date 18-12-2025
 */

#include <etl/optional.h>

#include <mbedtls/entropy.h>

#include <libeasytls/Tls.hpp>
#include <libeasytls/x509/Certificate.hpp>

namespace easytls
{
    class Client : public Tls
    {
    public:
        static etl::optional<Client> tryCreate(Bio&, etl::string_view hostname, x509::Certificate&);
        static inline int getCreateResult() { return createResult; }

        using Tls::handshake;
        using Tls::closeNotify;

        using Tls::read;
        using Tls::write;

        using Tls::setDebug;

        Client(Bio&, etl::string_view hostname, x509::Certificate&);
    private:

        static int createResult;
    };
}
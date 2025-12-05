#pragma once

#include <etl/optional.h>
#include <etl/span.h>

#include <mbedtls/pk.h>

namespace mbedtlspp
{
    class PrivateKey
    {
    public:
        using KeyData = etl::span<const unsigned char>;
        using Password = etl::span<const unsigned char>;

        static etl::optional<PrivateKey> parse(KeyData, Password = {});
        ~PrivateKey();
        
        PrivateKey(PrivateKey&& other) noexcept;
        PrivateKey& operator=(PrivateKey&& other) noexcept;

        inline auto& operator()() { return pkey; }

    protected:
        PrivateKey(); 

    private:
        PrivateKey(const PrivateKey&) = delete;
        PrivateKey& operator=(const PrivateKey&) = delete;

        mbedtls_pk_context pkey;

    };
}
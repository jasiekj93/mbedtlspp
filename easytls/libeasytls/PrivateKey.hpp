#pragma once

#include <etl/optional.h>
#include <etl/span.h>

#include <mbedtls/error.h>
#include <mbedtls/pk.h>

namespace easytls
{
    class PrivateKey
    {
    public:
        using KeyData = etl::span<const unsigned char>;
        using Password = etl::span<const unsigned char>;

        static etl::optional<PrivateKey> parse(KeyData, Password = {});
        static inline int getParseStatus() { return parseStatus; }

        ~PrivateKey();
        
        PrivateKey(PrivateKey&& other) noexcept;
        PrivateKey& operator=(PrivateKey&& other) noexcept;

        inline auto& operator()() { return pkey; }

    protected:
        PrivateKey(); 

    private:
        PrivateKey(const PrivateKey&) = delete;
        PrivateKey& operator=(const PrivateKey&) = delete;

        static int parseStatus;

        mbedtls_pk_context pkey;

    };
}
#pragma once

/**
 * @file Certificate.hpp
 * @author Adrian Szczepanski
 * @date 18-12-2025
 */

#include <etl/span.h>
#include <etl/optional.h>

#include <mbedtls/error.h>
#include <mbedtls/x509.h>
#include <mbedtls/x509_crt.h>

namespace easytls::x509
{
    class Certificate
    {
    public:
        // For PEM parsing, mbedTLS expects null-terminated data WITH the null terminator in size
        static etl::optional<Certificate> parse(etl::span<const unsigned char> buf);
        static inline int getParseStatus() { return parseStatus; }

        ~Certificate();

        Certificate(Certificate&& other) noexcept;
        Certificate& operator=(Certificate&& other) noexcept;

        inline auto& operator()() { return crt; }

    private:
        Certificate();

        static int parseStatus;

        mbedtls_x509_crt crt;

    };
}
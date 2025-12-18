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
        enum class Status : int
        {
            OK = 0,
            BAD_INPUT_DATA = MBEDTLS_ERR_X509_BAD_INPUT_DATA,
            CORRUPTION_DETECTED = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED,
            ALLOCATION_FAILED = MBEDTLS_ERR_X509_ALLOC_FAILED,
            INVALID_FORMAT = MBEDTLS_ERR_X509_INVALID_FORMAT,
            SIGNATURE_MISMATCH = MBEDTLS_ERR_X509_SIG_MISMATCH,
            FEATURE_UNAVAIBLE = MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE,
            UNKNOWN_OID = MBEDTLS_ERR_X509_UNKNOWN_OID,
            INVALID_SERIAL = MBEDTLS_ERR_X509_INVALID_SERIAL,
            INVALID_ALG = MBEDTLS_ERR_X509_INVALID_ALG,
            INVALID_NAME = MBEDTLS_ERR_X509_INVALID_NAME,
            INVALID_DATE = MBEDTLS_ERR_X509_INVALID_DATE,
            INVALID_SIGNATURE = MBEDTLS_ERR_X509_INVALID_SIGNATURE,
            INVALID_EXTENSIONS = MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
            UNKNOWN_SIG_ALG = MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG,
            VERIFICATION_FAILED = MBEDTLS_ERR_X509_CERT_VERIFY_FAILED,
            FILE_IO_ERROR = MBEDTLS_ERR_X509_FILE_IO_ERROR,
            BUFFER_TOO_SMALL = MBEDTLS_ERR_X509_BUFFER_TOO_SMALL,
            FATAL_ERROR = MBEDTLS_ERR_X509_FATAL_ERROR,
            ASN1_OUT_OF_DATA = MBEDTLS_ERR_ASN1_OUT_OF_DATA,
            ASN1_UNEXPECTED_TAG = MBEDTLS_ERR_ASN1_UNEXPECTED_TAG,
            ASN1_INVALID_LENGTH = MBEDTLS_ERR_ASN1_INVALID_LENGTH,
            ASN1_LENGTH_MISMATCH = MBEDTLS_ERR_ASN1_LENGTH_MISMATCH,
            ASN1_INVALID_DATA = MBEDTLS_ERR_ASN1_INVALID_DATA,
            ASN1_ALLOC_FAILED = MBEDTLS_ERR_ASN1_ALLOC_FAILED,
            X509_INVALID_VERSION = MBEDTLS_ERR_X509_INVALID_VERSION,
            X509_INVALID_SERIAL = MBEDTLS_ERR_X509_INVALID_SERIAL,
            X509_INVALID_ALG = MBEDTLS_ERR_X509_INVALID_ALG,
            X509_INVALID_NAME = MBEDTLS_ERR_X509_INVALID_NAME,
            X509_INVALID_DATE = MBEDTLS_ERR_X509_INVALID_DATE,
            X509_INVALID_SIGNATURE = MBEDTLS_ERR_X509_INVALID_SIGNATURE,
            X509_INVALID_EXTENSIONS = MBEDTLS_ERR_X509_INVALID_EXTENSIONS,
        };

        // For PEM parsing, mbedTLS expects null-terminated data WITH the null terminator in size
        static etl::optional<Certificate> parse(etl::span<const unsigned char> buf);
        static inline Status getParseStatus() { return parseStatus; }

        ~Certificate();

        Certificate(Certificate&& other) noexcept;
        Certificate& operator=(Certificate&& other) noexcept;

        inline auto& operator()() { return crt; }

    protected:

    private:
        Certificate();

        static Status parseStatus;

        mbedtls_x509_crt crt;

    };
}
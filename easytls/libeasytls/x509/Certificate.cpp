#include "Certificate.hpp"

using namespace easytls;
using namespace easytls::x509;

Certificate::Status Certificate::parseStatus = Certificate::Status::OK;

etl::optional<Certificate> Certificate::parse(etl::span<const unsigned char> buf)
{
    Certificate certificate;
    parseStatus = static_cast<Status>(mbedtls_x509_crt_parse(&certificate.crt, buf.data(), buf.size()));

    if (parseStatus == Status::OK)
        return etl::optional<Certificate>(etl::move(certificate));
    else
        return etl::nullopt;
}

Certificate::Certificate()
{
    mbedtls_x509_crt_init(&crt);
}

Certificate::~Certificate()
{
    mbedtls_x509_crt_free(&crt);
}

Certificate::Certificate(Certificate&& other) noexcept
{
    mbedtls_x509_crt_init(&crt);
    crt = other.crt;
    mbedtls_x509_crt_init(&other.crt);
}

Certificate& Certificate::operator=(Certificate&& other) noexcept
{
    if (this != &other)
    {
        mbedtls_x509_crt_free(&crt);
        crt = other.crt;
        mbedtls_x509_crt_init(&other.crt);
    }
    return *this;
}


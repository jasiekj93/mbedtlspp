#include "Psa.hpp"

#include <mbedtls/psa_util.h>

using namespace easytls;

int Psa::initResult = -1;

int Psa::init()
{
    if(not isInitialized())
    {
        initResult = static_cast<int>(psa_crypto_init());
    }

    return initResult;
}
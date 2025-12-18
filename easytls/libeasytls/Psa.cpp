#include "Psa.hpp"

#include <mbedtls/psa_util.h>

using namespace easytls;

bool Psa::initialized = false;
int Psa::initResult = 0;

void Psa::init()
{
    if(not initialized)
    {
        psa_status_t status = psa_crypto_init();

        if (status == PSA_SUCCESS) 
            initialized = true;

        initResult = status;
    }
}
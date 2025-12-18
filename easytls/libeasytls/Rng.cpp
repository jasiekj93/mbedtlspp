#include "Rng.hpp"

using namespace easytls;

static RandRng defaultRng;

std::shared_ptr<Rng> Rng::globalRng = std::make_shared<RandRng>(defaultRng);

void Rng::setGlobal(const std::shared_ptr<Rng> &rng)
{
    globalRng = rng;
}

int Rng::rand(void *context, unsigned char *buffer, size_t length)
{
    if (globalRng)
        return (*globalRng)(etl::span<unsigned char>(buffer, length));

    return -1;
}

int RandRng::operator()(etl::span<unsigned char> buffer)
{
    std::generate(buffer.begin(), buffer.end(), std::rand);
    return 0;
}


extern "C" int mbedtls_hardware_poll(void* data, unsigned char* output, size_t length, size_t* outputLength)
{
    (void)data; 
    int result = Rng::rand(nullptr, output, length);

    *outputLength = (result == 0) ? length : 0;
    return result;
}

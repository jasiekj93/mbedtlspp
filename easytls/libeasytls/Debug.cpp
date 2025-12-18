#include "Debug.hpp"

using namespace easytls;

std::shared_ptr<Debug> easytls::Debug::globalDebug = nullptr;

void Debug::setGlobal(const std::shared_ptr<Debug> &debug)
{
    globalDebug = debug;
}

void Debug::log(void*, int level, const char *file, int line, const char *message)
{
    if (globalDebug)
        globalDebug->print(level, etl::string_view(file), line, etl::string_view(message));
}

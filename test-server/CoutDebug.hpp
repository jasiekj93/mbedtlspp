#pragma once

#include <iostream>

#include <libeasytls/Debug.hpp>

class CoutDebug : public easytls::Debug
{
public:
    void print(int level, etl::string_view file, int line, etl::string_view message) override
    {
        std::cout << "[" << level << "] " << file.data() << ":" << line << ": " << message.data() << std::endl;
    }
};
#pragma once

/**
 * @file Debug.hpp
 * @author Adrian Szczepanski
 * @date 18-12-2025
 */

#include <memory>

#include <etl/string_view.h>

namespace easytls
{
    class Debug
    {
    public:
        static void setGlobal(const std::shared_ptr<Debug>& debug);
        static void log(void*, int level, const char* file, int line, const char* message);

        virtual ~Debug() = default;

        virtual void print(int level, etl::string_view file, int line, etl::string_view message) = 0;

    private:
        static std::shared_ptr<Debug> globalDebug;
    };
}
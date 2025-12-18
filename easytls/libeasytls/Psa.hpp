#pragma once

/**
 * @file Psa.hpp
 * @author Adrian Szczepanski
 * @date 18-12-2025
 */

namespace easytls
{
    class Psa
    {
    public:
        static void init();
        static inline bool isInitialized() { return initialized; }
        static inline int getInitResult() { return initResult; }

    private:
        static bool initialized;
        static int initResult;
    };
}
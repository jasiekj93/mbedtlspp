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
        static int init();
        static inline bool isInitialized() { return (initResult == 0); }

    private:
        static int initResult;
    };
}
#pragma once

#include <iostream>

namespace rs2fix::test {

inline int g_failures = 0;
inline int g_checks = 0;

inline void Check(
    const bool condition,
    const char* expression,
    const char* file,
    const int line) {
    ++g_checks;
    if (!condition) {
        ++g_failures;
        std::cerr << file << ':' << line
                  << ": CHECK failed: " << expression << '\n';
    }
}

} // namespace rs2fix::test

#define RS2_CHECK(expression) \
    ::rs2fix::test::Check( \
        static_cast<bool>(expression), #expression, __FILE__, __LINE__)

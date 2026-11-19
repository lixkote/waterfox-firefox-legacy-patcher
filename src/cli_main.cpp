#include <cstdio>
#include <fstream>
#include <chrono>
#include <iterator>
#include "core.h"

int main(int argc, char** argv) {
    if (argc < 3) { std::fprintf(stderr, "usage: %s in.dll out.dll\n", argv[0]); return 2; }
    std::ifstream f(argv[1], std::ios::binary);
    std::vector<uint8_t> in((std::istreambuf_iterator<char>(f)), {});
    std::vector<uint8_t> out;
    sse42::Stats st;
    auto t0 = std::chrono::steady_clock::now();
    auto r = sse42::PatchImage(in, out, st, [](const std::string& s) { std::printf("%s\n", s.c_str()); });
    double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
    std::printf("%s: %s in %.0f ms | popcnt=%u crc32=%u pcmpgtq=%u pcmpstr=%u | direct=%u cave=%u steal=%u | fast=%u generic=%u | SKIPPED=%u\n",
                argv[1], sse42::ResultName(r), ms, st.popcnt, st.crc32, st.pcmpgtq, st.pcmpstr, st.direct, st.viaCave,
                st.viaSteal, st.inlineFast, st.generic, st.skipped);
    if (r == sse42::Result::Patched) {
        std::ofstream o(argv[2], std::ios::binary);
        o.write((const char*)out.data(), out.size());
    }
    return r == sse42::Result::Error ? 1 : 0;
}

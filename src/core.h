#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace sse42 {

using LogFn = std::function<void(const std::string&)>;

struct Stats {

    unsigned popcnt = 0, crc32 = 0, pcmpgtq = 0, pcmpstr = 0;

    unsigned direct = 0, viaCave = 0, viaSteal = 0;
    unsigned inlineFast = 0, generic = 0;
    unsigned skipped = 0;
    unsigned total() const { return popcnt + crc32 + pcmpgtq + pcmpstr; }
};

enum class Result {
    Patched,
    NothingToDo,
    AlreadyPatched,
    NotX64PE,
    Error,
};

Result PatchImage(const std::vector<uint8_t>& in, std::vector<uint8_t>& out,
                  Stats& stats, const LogFn& log);

Result ScanImage(const std::vector<uint8_t>& in, Stats& stats, const LogFn& log);

const char* ResultName(Result r);

}

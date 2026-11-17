#include "companion/build_identity.h"

namespace rs2fix {
namespace {

constexpr Sha256Digest kPr1CrashFullDump{
    0x15, 0x5e, 0xbc, 0x77, 0xd2, 0xfa, 0x57, 0x4f,
    0x0a, 0x94, 0x70, 0x98, 0x39, 0xef, 0x1d, 0xf6,
    0xa3, 0xda, 0x82, 0xb2, 0x78, 0xc8, 0x46, 0xf1,
    0x42, 0x23, 0x96, 0x7b, 0x05, 0x8c, 0x46, 0x22,
};

constexpr Sha256Digest kPr1StockBaseline{
    0x58, 0x20, 0xf0, 0xda, 0x82, 0xd7, 0xc2, 0x90,
    0x3d, 0xe3, 0x1e, 0x08, 0x65, 0x32, 0x0d, 0x9e,
    0x70, 0xa0, 0xbf, 0x74, 0xf7, 0x8f, 0x83, 0xc8,
    0x3d, 0xb4, 0xf9, 0xde, 0xea, 0xeb, 0x1d, 0xef,
};

} // namespace

BuildIdentity ClassifyBuild(
    const Sha256Digest& digest,
    const bool digestValid) noexcept {
    if (!digestValid) {
        return BuildIdentity::Indeterminate;
    }
    if (digest == kPr1CrashFullDump) {
        return BuildIdentity::Pr1CrashFullDump;
    }
    if (digest == kPr1StockBaseline) {
        return BuildIdentity::Pr1StockBaseline;
    }
    if (digest == kCurrentStockDigest) {
        return BuildIdentity::CurrentStock;
    }
    if (digest == kCurrentFullDumpDigest) {
        return BuildIdentity::CurrentFullDump;
    }
    return BuildIdentity::Unknown;
}

const char* BuildIdentityName(const BuildIdentity identity) noexcept {
    switch (identity) {
    case BuildIdentity::Pr1CrashFullDump:
        return "pr1-crash-full-dump";
    case BuildIdentity::Pr1StockBaseline:
        return "pr1-stock-baseline";
    case BuildIdentity::CurrentStock:
        return "current-stock";
    case BuildIdentity::CurrentFullDump:
        return "current-full-dump";
    case BuildIdentity::Unknown:
        return "unknown";
    case BuildIdentity::Indeterminate:
        return "indeterminate";
    }
    return "indeterminate";
}

} // namespace rs2fix

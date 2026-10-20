#include "companion/leech_recovery_wire.h"
#include "companion/steam_reporting_status.h"
#include <Windows.h>
#include <cstring>

#if !defined(_MSC_VER) || !defined(_M_X64)
#error Recovery publication requires the Windows MSVC AMD64 aligned-store contract.
#endif

extern "C" { rs2fix::reporting::RecoveryStatusWireV1 RS2LeechRecovery_StatusV1{}; }
namespace rs2fix::reporting {
namespace {
void StorePayload(ReportRecoveryPayload& to, const ReportRecoveryPayload& from) noexcept {
    for (std::size_t offset = 0; offset < sizeof(from); offset += 8) {
        std::uint64_t value{};
        std::memcpy(&value, reinterpret_cast<const unsigned char*>(&from) + offset, 8);
        auto* word = reinterpret_cast<volatile LONG64*>(reinterpret_cast<unsigned char*>(&to) + offset);
        WriteRelease64(word, static_cast<LONG64>(value));
    }
}
bool LocalRead(void* context, std::size_t offset, void* output, std::size_t size) noexcept {
    const auto& wire = *static_cast<const RecoveryStatusWireV1*>(context);
    if (offset > sizeof(wire) || size > sizeof(wire) - offset || offset % 8 || size % 8) return false;
    for (std::size_t at = 0; at < size; at += 8) {
        const auto* word = reinterpret_cast<const std::uint64_t*>(reinterpret_cast<const unsigned char*>(&wire) + offset + at);
        const auto value = ReadStatusWord(*word);
        std::memcpy(static_cast<unsigned char*>(output) + at, &value, 8);
    }
    return true;
}
}
bool InitializeRecoveryStatus(RecoveryStatusWireV1& wire, const StatusHeader& identity) noexcept {
    if (!ReportingIdentityValidV3(identity) ||
        InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(&wire.headerReady), 2, 0) != 0) return false;
    wire.schema = kRecoveryStatusSchemaV1; wire.bytes = sizeof(wire);
    wire.artifactVersion = kRecoveryArtifactVersion; wire.pid = identity.pid;
    std::memcpy(wire.runId, identity.runId, sizeof(wire.runId));
    StoreStatusWord(wire.ownerSequence, 1);
    StorePayload(wire.payload, ReportRecoveryPayload{});
    StoreStatusWord(wire.ownerSequence, 2);
    StoreStatusWord(wire.headerReady, 1);
    return true;
}
bool PublishRecoveryStatus(RecoveryStatusWireV1& wire, const ReportRecoveryPayload& payload) noexcept {
    if (!RecoveryPayloadValid(payload) || ReadStatusWord(wire.headerReady) != 1 ||
        wire.schema != kRecoveryStatusSchemaV1 || wire.bytes != sizeof(wire) ||
        wire.artifactVersion != kRecoveryArtifactVersion || !wire.pid) return false;
    unsigned runBits{};
    for (auto byte : wire.runId) runBits |= byte;
    if (!runBits) return false;
    const auto before = ReadStatusWord(wire.ownerSequence);
    if (before < 2 || (before & 1) || before > UINT64_MAX - 2) return false;
    StoreStatusWord(wire.ownerSequence, before + 1);
    StorePayload(wire.payload, payload);
    StoreStatusWord(wire.ownerSequence, before + 2);
    return true;
}
RecoverySnapshotResult ReadRecoveryStatusSnapshot(const RecoveryStatusWireV1& wire, RecoveryStatusSnapshot* output) noexcept {
    return ReadRecoveryStatusSnapshot(RecoveryReadOps{const_cast<RecoveryStatusWireV1*>(&wire), LocalRead}, output);
}
RecoverySnapshotResult ReadRecoveryStatusSnapshot(const RecoveryStatusWireV1& wire,
    const StatusHeader& identity, RecoveryStatusSnapshot* output) noexcept {
    return ReadRecoveryStatusSnapshot(RecoveryReadOps{const_cast<RecoveryStatusWireV1*>(&wire), LocalRead}, identity, output);
}
} // namespace rs2fix::reporting

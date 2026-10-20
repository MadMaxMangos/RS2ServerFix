#pragma once
#include "shared/native_log_framing.h"
#include <cstdint>

namespace rs2fix::reporting {
enum class ReceiptDisposition { Ignored, Accepted, AwaitingSubmission, Gap, Corrupt };
struct ReceiptMatchOps {
    void* context;
    ReceiptDisposition (*match)(void*,const char* message,std::size_t bytes) noexcept;
};
// One receipt worker owns this POD. offset is the processed offset, not the
// end of the last OS read: an unprocessed read suffix must be read again.
struct ReceiptScanner {
    std::uint64_t offset;
    native_log::PrefixMode prefixMode;
    std::uint8_t runId[16];
    std::size_t carry;
    bool skipInitialSuffix;
    bool oversized;
    bool awaitingSubmission;
    bool failed;
    char line[native_log::kLineLimit];
};
struct ReceiptScanResult {
    std::size_t consumed;
    ReceiptDisposition disposition;
};
bool InitializeReceiptScanner(ReceiptScanner&,std::uint64_t initialEOF,
    bool atLineBoundary,native_log::PrefixMode,const std::uint8_t (&runId)[16]) noexcept;
// EOF and partial lines are not loss. A completed later/malformed selected
// frame can be loss. No I/O, allocation, clocks or native object access here.
ReceiptScanResult ScanReceiptChunk(ReceiptScanner&,const ReceiptMatchOps&,
    const char*,std::size_t bytes) noexcept;
// Worker calls only after the held matched receipt has been acknowledged
// against a coherent normally-returned owner submission publication.
bool ResumeReceiptScanner(ReceiptScanner&) noexcept;
} // namespace rs2fix::reporting

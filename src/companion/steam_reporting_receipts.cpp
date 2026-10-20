#include "companion/steam_reporting_receipts.h"
#include <cstring>

namespace rs2fix::reporting {
bool InitializeReceiptScanner(ReceiptScanner& s,std::uint64_t initialEOF,
    bool boundary,native_log::PrefixMode mode,const std::uint8_t (&runId)[16]) noexcept {
    s={};
    if (mode!=native_log::PrefixMode::LogOnly && mode!=native_log::PrefixMode::ElapsedTime)
        return false;
    s.offset=initialEOF; s.prefixMode=mode; s.skipInitialSuffix=!boundary;
    std::memcpy(s.runId,runId,sizeof(s.runId));
    return true;
}
ReceiptScanResult ScanReceiptChunk(ReceiptScanner& s,const ReceiptMatchOps& ops,
    const char* bytes,std::size_t count) noexcept {
    if (s.failed) return {0,ReceiptDisposition::Corrupt};
    if (s.awaitingSubmission) return {0,ReceiptDisposition::AwaitingSubmission};
    if ((!bytes && count) || !ops.match || s.carry>sizeof(s.line)) {
        s.failed=true; return {0,ReceiptDisposition::Corrupt};
    }
    ReceiptScanResult result{0,ReceiptDisposition::Ignored};
    for (;result.consumed<count;) {
        if (s.offset==UINT64_MAX) {
            s.failed=true; result.disposition=ReceiptDisposition::Corrupt; break;
        }
        const auto c=bytes[result.consumed++];
        ++s.offset;
        if (s.skipInitialSuffix) {
            if (c=='\n') s.skipInitialSuffix=false;
            continue;
        }
        if (s.carry<sizeof(s.line)) s.line[s.carry++]=c;
        else s.oversized=true;
        if (c!='\n') continue;
        auto disposition=ReceiptDisposition::Ignored;
        if (s.oversized) {
            // An 8 KiB+ retained prefix cannot still be a partial native prefix
            // or marker. Incomplete therefore means selected, but we waited
            // for the actual newline before declaring the oversized receipt bad.
            const auto view=native_log::InspectLine(s.line,s.carry,s.prefixMode,false);
            if (view.messageOffset && native_log::BelongsToRun(s.line+view.messageOffset,
                s.carry-view.messageOffset,s.runId)) disposition=ReceiptDisposition::Corrupt;
        } else {
            const auto view=native_log::InspectLine(s.line,s.carry,s.prefixMode,true);
            const bool scoped=view.messageOffset && native_log::BelongsToRun(s.line+view.messageOffset,
                s.carry-view.messageOffset,s.runId);
            if (scoped && view.kind==native_log::LineKind::Malformed) disposition=ReceiptDisposition::Corrupt;
            else if (scoped && view.kind==native_log::LineKind::Frame)
                disposition=ops.match(ops.context,s.line+view.messageOffset,view.messageBytes);
        }
        s.carry=0; s.oversized=false;
        if (disposition==ReceiptDisposition::Ignored) continue;
        result.disposition=disposition;
        if (disposition==ReceiptDisposition::AwaitingSubmission) {
            s.awaitingSubmission=true; break;
        }
        if (disposition==ReceiptDisposition::Gap || disposition==ReceiptDisposition::Corrupt) {
            s.failed=true; break;
        }
    }
    return result;
}
bool ResumeReceiptScanner(ReceiptScanner& s) noexcept {
    if (s.failed || !s.awaitingSubmission || s.carry || s.oversized) return false;
    s.awaitingSubmission=false; return true;
}
} // namespace rs2fix::reporting

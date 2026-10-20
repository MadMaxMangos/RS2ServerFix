#pragma once
#include "companion/steam_reporting_log_file.h"
#include "companion/steam_reporting_pipeline.h"

namespace rs2fix::reporting {
struct NativeWorkerClock {
    void* context;
    bool (*sample)(void*,std::uint64_t*) noexcept;
};
const NativeWorkerClock& ProductionNativeWorkerClock() noexcept;
// Sole-worker storage. Preparation/OS-thread/mailbox ownership is handled by
// the enclosing transport; this cycle core is also exercised with own files.
struct NativeReceiptWorker {
    StatusWireV3* status;
    ReportRingV3* ring;
    NativeFormatContext format;
    NativeHashOps hash;
    NativeWorkerClock clock;
    NativeLogFile file;
    NativePipeline pipeline;
    ReceiptScanner scanner;
    WorkerTransport counters;
    std::uint64_t lastClock;
    std::uint64_t lastCycle;
    std::uint64_t qualifiedEpoch;
    std::uint64_t receiptWaitSequence,receiptWaitStartedQpc;
    bool initialized;
    bool haveCycle;
    bool clockFailed;
    bool receiptWaitActive;
    char readBuffer[64*1024];
};
// No native pointer is accepted. format's calibration/startup identity is copied
// before hooks; the verified path/file identity is supplied later on the worker.
bool InitializeNativeReceiptWorker(NativeReceiptWorker&,StatusWireV3&,ReportRingV3&,
    const NativeFormatContext&,const NativeHashOps&,const NativeWorkerClock&) noexcept;
TransportReason QualifyNativeReceiptFile(NativeReceiptWorker&,const std::uint16_t* path,
    std::size_t chars,std::uint64_t prefixMode,std::uint64_t epoch) noexcept;
// Does no native logging. Runs at most once per250ms, max256KiB actual bytes read,
// inclusive of unrelated game lines and suffix rereads. EOF never busy-loops.
void CycleNativeReceipts(NativeReceiptWorker&) noexcept;
void CloseNativeReceipts(NativeReceiptWorker&) noexcept;
}

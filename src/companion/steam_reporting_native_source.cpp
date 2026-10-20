#include "companion/steam_reporting_native_source.h"
#include <cstring>
#include <initializer_list>
#include <limits>

namespace rs2fix::reporting {
namespace {
constexpr NativeLogLayout kLayout{
    0x146F7E8, 0x14CC330, 0xED4BF0,
    0xED4C50, 0xED4CF0, 0xED4CB0, 0xEC6468, 0xED4D30,
    0xEA52F0, 0x14B9890, 0x11CE640,
    0x14C199C, 0x14C193C, 0x14C1970, 0x14CC288,
    0x14F00C4, 0x1772860, 0x1772B14, 0x1772B18, 0x1772B20, 0x1772B24
};
class Reader {
public:
    explicit Reader(const NativeLogReadContext& context) noexcept : c_(context),
        l_(context.layout ? *context.layout : kLayout) {}
    bool Unavailable() const noexcept { return unavailable_; }

    TransportReason Read(NativeLogSnapshot& out) const noexcept {
        using T = TransportReason;
        std::uint32_t critical{}, exit{}, force{}, times{}, initialized{};
        if (!Global(l_.criticalError, critical) || !Global(l_.requestingExit, exit) ||
            !Global(l_.forceFlush, force) || !Global(l_.logTimes, times) ||
            !Global(l_.suppressionInitialized, initialized)) return T::ProfileUnsafe;
        // Never enter native recursion/exception handling just to obtain a log.
        // A shutdown/critical/reentry state refuses this opportunity; it is
        // not evidence that immutable profile bytes changed. Lifecycle handling
        // remains the caller's responsibility and must not log while unwinding.
        if (critical || exit) return T::AwaitingLogger;
        for (auto rva : {l_.fileReentry, l_.debugReentry, l_.inheritedReentry, l_.consoleReentry}) {
            std::uint32_t reentry{};
            if (!Global(rva, reentry)) return T::ProfileUnsafe;
            if (reentry) return T::AwaitingLogger;
        }
        if (!force) return T::ForceFlushMissing;
        if (times > 1) return T::FramingUnsupported;
        out.prefixMode = static_cast<std::uint64_t>(times ? native_log::PrefixMode::ElapsedTime : native_log::PrefixMode::LogOnly);
        if (initialized) {
            std::uintptr_t table{}, entry{};
            std::uint64_t flags{};
            if (!Global(l_.nameTable, table)) return T::ProfileUnsafe;
            if (!table) return T::AwaitingLogger;
            if (!Field(table, 0x17C0, entry)) return T::ProfileUnsafe;
            if (!entry) return T::AwaitingLogger;
            if (!Field(entry, 0, flags)) return T::ProfileUnsafe;
            if (flags & 0x100000000000ULL) return T::CategorySuppressed;
        } else return T::AwaitingLogger;

        if (!Global(l_.logSlot, out.redirector)) return T::ProfileUnsafe;
        if (!out.redirector) return T::AwaitingLogger;
        if (out.redirector != Image(l_.redirectorObject) || !Vtable(out.redirector, l_.redirectorVtable) ||
            !Range(out.redirector, 0x7C, true))
            return T::ProfileUnsafe;
        std::uint32_t master{}, backlog{};
        std::uintptr_t array{};
        std::int32_t count{}, capacity{};
        if (!Field(out.redirector, 0x44, master) || !Field(out.redirector, 0x48, backlog) ||
            !Field(out.redirector, 0x34, array) || !Field(out.redirector, 0x3C, count) ||
            !Field(out.redirector, 0x40, capacity)) return T::ProfileUnsafe;
        if (!master) return T::AwaitingLogger;
        if (master != c_.ownerThreadId) return T::ProfileUnsafe;
        if (backlog || count == 0) return T::AwaitingLogger;
        // Native array capacity may include allocator slack. Only active
        // elements are read/called; unused capacity grants no admission.
        if (count < 0 || capacity < count || count > static_cast<int>(kNativeSinkLimit)) return T::SinkUnsupported;
        if (!Bytes(array, out.sinks, static_cast<std::size_t>(count) * sizeof(std::uintptr_t)))
            return T::ProfileUnsafe;
        out.sinkCount = static_cast<std::uint32_t>(count);
        for (std::size_t i = 0; i < out.sinkCount; ++i) {
            const auto sink = out.sinks[i];
            if (!Field(sink, 0, out.sinkVtables[i])) return T::ProfileUnsafe;
            for (std::size_t j = 0; j < i; ++j)
                if (out.sinks[j] == sink) return T::SinkUnsupported;
            const auto vt = out.sinkVtables[i];
            if (vt == Image(l_.fileVtable)) {
                if (out.file) return T::SinkUnsupported;
                out.file = sink;
            } else if (vt == Image(l_.inheritedVtable)) {
                if (!Range(sink, 0x28, false)) return T::ProfileUnsafe;
                std::uintptr_t handle{};
                std::uint32_t connected{};
                if (!Field(sink, 0x14, handle) || !Field(sink, 0x1C, connected)) return T::ProfileUnsafe;
                if (handle == UINTPTR_MAX) {
                    if (!Field(sink, 0x20, out.inheritedFallbacks[i]) ||
                        !Vtable(out.inheritedFallbacks[i], l_.consoleVtable) ||
                        !Range(out.inheritedFallbacks[i], 0x1C, false)) return T::SinkUnsupported;
                } else if (connected) {
                    // Connected-pipe FString/WriteFile path is not enabled by
                    // the fallback-console proof. Refuse until qualified fully.
                    return T::SinkUnsupported;
                }
            } else if (vt != Image(l_.consoleVtable) && vt != Image(l_.debugVtable) &&
                vt != Image(l_.eventVtable)) return T::SinkUnsupported;
            else if (!Range(sink, vt == Image(l_.debugVtable) ? 0x14 : 0x1C, false))
                return T::ProfileUnsafe;
        }
        if (!out.file) return T::SinkUnsupported;
        if (!Range(out.file, 0x828, true)) return T::ProfileUnsafe;
        std::uintptr_t manager{};
        if (!Global(l_.managerSlot, manager) || !Vtable(manager, l_.managerVtable))
            return T::FileManagerUnsupported;
        std::uint32_t opened{}, dead{}, suppressTag{}, newline{};
        if (!Field(out.file, 0x14, out.archive) || !Field(out.file, 0x81C, opened) ||
            !Field(out.file, 0x820, dead) || !Field(out.file, 0xC, suppressTag) ||
            !Field(out.file, 0x10, newline)) return T::ProfileUnsafe;
        if (!out.archive || !opened || dead) return T::AwaitingLogger;
        if (suppressTag || !newline) return T::FramingUnsupported;
        if (!Vtable(out.archive, l_.archiveVtable)) return T::ProfileUnsafe;
        // A legitimate archive close/reopen can temporarily remove writable
        // storage or invalidate its OS handle. Refuse without converting this
        // live transition into an immutable-profile failure.
        if (!Range(out.archive, 0x10B0, true)) return T::AwaitingLogger;
        std::int32_t buffered{};
        std::uint32_t archiveError{};
        if (!Field(out.archive, 0x84, out.archiveHandle) ||
            !Field(out.archive, 0xAC, buffered) || !Field(out.archive, 0x38, archiveError)) return T::ProfileUnsafe;
        if (!out.archiveHandle || out.archiveHandle == UINTPTR_MAX) return T::AwaitingLogger;
        if (buffered < 0 || buffered > 4096) return T::ProfileUnsafe;
        if (archiveError) return T::ReceiptUnavailable;
        if (!BytesAt(out.file, 0x1C, out.path, sizeof(out.path))) return T::ProfileUnsafe;
        while (out.pathChars < 1024 && out.path[out.pathChars]) ++out.pathChars;
        if (!out.pathChars || out.pathChars == 1024) return T::FramingUnsupported;
        // Ignore unused native filename buffer bytes when comparing observations.
        std::memset(out.path + out.pathChars, 0, (1024 - out.pathChars) * sizeof(out.path[0]));
        // This is only the syntax gate. The receipt worker must validate the
        // fixed drive, every path component/reparse point, and held file identity.
        if (out.pathChars < 4 || !((out.path[0] >= 'A' && out.path[0] <= 'Z') ||
                (out.path[0] >= 'a' && out.path[0] <= 'z')) || out.path[1] != ':' || out.path[2] != '\\')
            return T::FramingUnsupported;
        for (std::size_t i = 2; i < out.pathChars; ++i)
            if (out.path[i] == ':' || out.path[i] < 0x20) return T::FramingUnsupported;
        return T::None;
    }
private:
    const NativeLogReadContext& c_;
    const NativeLogLayout& l_;
    mutable bool unavailable_{};
    std::uintptr_t Image(std::uint32_t rva) const noexcept {
        return rva && rva < c_.hostImageSize && c_.hostBase <= UINTPTR_MAX - rva ? c_.hostBase + rva : 0;
    }
    bool Range(std::uintptr_t address, std::size_t bytes, bool writable) const noexcept {
        if (!address || !bytes || bytes > 0x1100 || address > UINTPTR_MAX - bytes) return false;
        auto cursor = address;
        const auto end = address + bytes;
        for (unsigned visited = 0; cursor < end && visited < 8; ++visited) {
            MemoryRegion region{};
            DWORD error{};
            if (!c_.memory.query(c_.memory.context, cursor, &region, &error)) {
                unavailable_=true; return false;
            }
            if (region.state != MEM_COMMIT || region.base > cursor || !region.size ||
                !region.allocationBase || region.allocationBase > region.base ||
                region.base > UINTPTR_MAX - region.size || cursor - region.base >= region.size ||
                (region.type != MEM_PRIVATE && region.type != MEM_IMAGE) ||
                (region.type == MEM_IMAGE && region.allocationBase != c_.hostBase) ||
                (region.protect != PAGE_READWRITE && (writable || region.protect != PAGE_READONLY))) return false;
            const auto next = region.base + region.size;
            cursor = next < end ? next : end;
        }
        return cursor == end;
    }
    bool Bytes(std::uintptr_t address, void* output, std::size_t bytes) const noexcept {
        DWORD error{};
        if (bytes>2048 || !Range(address,bytes,false)) return false;
        if (!c_.memory.read(c_.memory.context,address,output,bytes,&error)) {
            unavailable_=true; return false;
        }
        return true;
    }
    bool BytesAt(std::uintptr_t base, std::size_t offset, void* out, std::size_t size) const noexcept {
        return base && offset <= UINTPTR_MAX - base && Bytes(base + offset, out, size);
    }
    template<class T> bool Field(std::uintptr_t base, std::size_t offset, T& out) const noexcept {
        return BytesAt(base, offset, &out, sizeof(out));
    }
    template<class T> bool Global(std::uint32_t rva, T& out) const noexcept {
        DWORD error{};
        if (rva>=c_.hostImageSize || sizeof(out)>c_.hostImageSize-rva) return false;
        if (!ReadImageRange(c_.hostBase,c_.hostImageSize,rva,&out,sizeof(out),c_.memory,&error)) {
            unavailable_=true; return false;
        }
        return true;
    }
    bool Vtable(std::uintptr_t object, std::uint32_t expected) const noexcept {
        std::uintptr_t actual{};
        return Image(expected) && Field(object, 0, actual) && actual == Image(expected);
    }
};
} // namespace

const NativeLogLayout& ProductionNativeLogLayout() noexcept { return kLayout; }
TransportReason ReadNativeLogSnapshot(const NativeLogReadContext& context, NativeLogSnapshot* output) noexcept {
    if (output) *output = {};
    if (!output || !context.memory.query || !context.memory.read || !context.hostBase ||
        !context.hostImageSize || context.hostBase > UINTPTR_MAX - context.hostImageSize ||
        !context.ownerThreadId) return TransportReason::ProfileUnsafe;
    Reader reader(context);
    NativeLogSnapshot first{}, second{};
    auto reason = reader.Read(first);
    if (reason != TransportReason::None) return reader.Unavailable() ? TransportReason::AwaitingLogger : reason;
    reason = reader.Read(second);
    if (reason != TransportReason::None) return reader.Unavailable() ? TransportReason::AwaitingLogger : reason;
    if (std::memcmp(&first, &second, sizeof(first))) return TransportReason::AwaitingLogger;
    *output = second;
    return TransportReason::None;
}
} // namespace rs2fix::reporting

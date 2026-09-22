#include "companion/steam_reporting_prepared.h"
#include "companion/steam_reporting_json.h"
#include "companion/steam_reporting_read_scope.h"

#include <limits>

namespace rs2fix::reporting {
namespace {
constexpr PreparedLayout kProductionLayout{
    0x14AAD20, 0x14AAD28, 0x14AAD48, 0x14AAD68, 0x14AAD70, 0x1798800, 0x14AAD88};
constexpr std::size_t kRegions = 32;
constexpr std::size_t kMemberStride = 0x20;

struct Scrubber {
    char* bytes;
    std::size_t size;
    ~Scrubber() noexcept { if (bytes && size) SecureZeroMemory(bytes, size); }
};
struct NativeString {
    std::uintptr_t data;
    std::uint64_t length;
    std::uint64_t capacity;
    bool inImage;
};
struct Headers {
    std::uint32_t service;
    std::uintptr_t ip;
    std::int32_t ipNum;
    std::int32_t ipCapacity;
    NativeString registration;
    NativeString gameMode;
    std::uint32_t maximum;
    std::uintptr_t membersBegin;
    std::uintptr_t membersEnd;
    std::uintptr_t membersCapacity;
    std::uint32_t membersCount;
};

bool Add(std::uintptr_t base, std::size_t amount, std::uintptr_t* output) noexcept {
    if (!base || amount > (std::numeric_limits<std::uintptr_t>::max)() - base) return false;
    *output = base + amount;
    return true;
}
bool SameString(const NativeString& a, const NativeString& b) noexcept {
    return a.data == b.data && a.length == b.length && a.capacity == b.capacity && a.inImage == b.inImage;
}
bool SameHeaders(const Headers& a, const Headers& b) noexcept {
    return a.service == b.service && a.ip == b.ip && a.ipNum == b.ipNum && a.ipCapacity == b.ipCapacity &&
        SameString(a.registration, b.registration) && SameString(a.gameMode, b.gameMode) &&
        a.maximum == b.maximum && a.membersBegin == b.membersBegin && a.membersEnd == b.membersEnd &&
        a.membersCapacity == b.membersCapacity && a.membersCount == b.membersCount;
}

class PreparedReader {
public:
    PreparedReader(const PreparedReadContext& context,ImageSections& sections) noexcept : context_(context),sections_(sections) {}

    Reason ReadHeaders(Headers& output) const noexcept {
        output = {};
        const auto& layout = context_.layout ? *context_.layout : kProductionLayout;
        if (!Global(layout.service, output.service)) return Reason::PreparedUnavailable;
        if (output.service != 3) return Reason::Unregistered;
        if (!Global(layout.publicIp, output.ip) || !Global(layout.publicIp + 8, output.ipNum) ||
            !Global(layout.publicIp + 12, output.ipCapacity) || output.ipNum <= 1 ||
            output.ipNum > output.ipCapacity || output.ipCapacity > 1024 ||
            !output.ip || (output.ip & 1)) return Reason::PublicIpUnavailable;
        std::uintptr_t ipEnd{}, ipTerminator{};
        if (!Add(output.ip, static_cast<std::size_t>(output.ipCapacity) * sizeof(std::uint16_t), &ipEnd) ||
            !PrivateRange(output.ip, static_cast<std::size_t>(output.ipNum) * sizeof(std::uint16_t)) ||
            !Add(output.ip, static_cast<std::size_t>(output.ipNum - 1) * sizeof(std::uint16_t), &ipTerminator))
            return Reason::PublicIpUnavailable;
        std::uint16_t ipNul{};
        // This is the sole public-IP content read: its expected final NUL.
        if (!PrivateRead(ipTerminator, &ipNul, sizeof(ipNul)) || ipNul != 0) return Reason::PublicIpUnavailable;

        auto reason = StringHeader(layout.registration, 1024, output.registration);
        if (reason != Reason::None) return reason;
        reason = StringHeader(layout.gameMode, kJsonBytes, output.gameMode);
        if (reason != Reason::None) return reason;
        if (!Global(layout.maximum, output.maximum) || !Global(layout.members, output.membersBegin) ||
            !Global(layout.members + 8, output.membersEnd) || !Global(layout.members + 16, output.membersCapacity))
            return Reason::PreparedUnavailable;
        if (!output.membersBegin) {
            if (output.membersEnd || output.membersCapacity) return Reason::PreparedMalformed;
        } else {
            if ((output.membersBegin & 7) || output.membersEnd < output.membersBegin ||
                output.membersCapacity < output.membersEnd) return Reason::PreparedMalformed;
            const auto used = output.membersEnd - output.membersBegin;
            const auto allocated = output.membersCapacity - output.membersBegin;
            if (used % kMemberStride || allocated % kMemberStride) return Reason::PreparedMalformed;
            if (allocated / kMemberStride > 4096) return Reason::PreparedLimit;
            // Query only. Never read a std::string element or member identity.
            if (!PrivateRange(output.membersBegin, allocated ? allocated : 1)) return Reason::PreparedUnavailable;
            output.membersCount = static_cast<std::uint32_t>(used / kMemberStride);
        }
        unsigned char nul{};
        std::uintptr_t end{};
        if (!Add(output.gameMode.data, static_cast<std::size_t>(output.gameMode.length), &end) ||
            !StringRead(output.gameMode, end, &nul, sizeof(nul))) return Reason::PreparedUnavailable;
        if (nul) return Reason::PreparedMalformed;
        return Reason::None;
    }
    bool Copy(const NativeString& string, char* output) const noexcept {
        return StringRead(string, string.data, output, static_cast<std::size_t>(string.length));
    }

private:
    const PreparedReadContext& context_;
    ImageSections& sections_;

    bool PrivateRange(std::uintptr_t address, std::size_t size) const noexcept {
        std::uintptr_t end{};
        if (!size || !Add(address, size, &end)) return false;
        auto cursor = address;
        for (std::size_t n = 0; cursor < end && n < kRegions; ++n) {
            MemoryRegion region{};
            DWORD error{};
            if (!context_.memory.query(context_.memory.context, cursor, &region, &error) ||
                region.state != MEM_COMMIT || region.type != MEM_PRIVATE || region.protect != PAGE_READWRITE ||
                !region.allocationBase || region.allocationBase > region.base || region.base > cursor ||
                !region.size || region.size > (std::numeric_limits<std::uintptr_t>::max)() - region.base ||
                region.base + region.size <= cursor) return false;
            const auto next = region.base + region.size;
            cursor = next < end ? next : end;
        }
        return cursor == end;
    }
    bool PrivateRead(std::uintptr_t address, void* output, std::size_t size) const noexcept {
        DWORD error{};
        return PrivateRange(address, size) &&
            context_.memory.read(context_.memory.context, address, output, size, &error);
    }
    bool ImageRange(std::uint32_t rva, std::size_t size) const noexcept {
        DWORD error{};
        return sections_.Matches(rva, size,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE) &&
            ImageRangeProtection(context_.hostBase, context_.hostImageSize,
                rva, size, PAGE_READWRITE, context_.memory, &error);
    }
    bool ImageRead(std::uint32_t rva, void* output, std::size_t size) const noexcept {
        DWORD error{};
        return ImageRange(rva, size) && ReadImageRange(context_.hostBase, context_.hostImageSize,
            rva, output, size, context_.memory, &error);
    }
    template<class T> bool Global(std::uint32_t rva, T& value) const noexcept {
        return ImageRead(rva, &value, sizeof(value));
    }
    bool StringRead(const NativeString& string, std::uintptr_t address, void* output, std::size_t size) const noexcept {
        if (!string.inImage) return PrivateRead(address, output, size);
        if (address < context_.hostBase || address - context_.hostBase >= context_.hostImageSize) return false;
        return ImageRead(static_cast<std::uint32_t>(address - context_.hostBase), output, size);
    }
    Reason StringHeader(std::uint32_t rva, std::size_t limit, NativeString& output) const noexcept {
        if (!Global(rva + 0x10, output.length) || !Global(rva + 0x18, output.capacity))
            return Reason::PreparedUnavailable;
        if (output.length > output.capacity || output.capacity == UINT64_MAX) return Reason::PreparedMalformed;
        if (!output.length) return Reason::PreparedUnavailable;
        if (output.length > limit) return Reason::PreparedLimit;
        output.inImage = output.capacity < 16;
        if (output.inImage) {
            if (!Add(context_.hostBase, rva, &output.data)) return Reason::PreparedMalformed;
        } else if (!Global(rva, output.data)) return Reason::PreparedUnavailable;
        std::uintptr_t capacityEnd{}, usedEnd{};
        if (!Add(output.data, static_cast<std::size_t>(output.capacity + 1), &capacityEnd) ||
            !Add(output.data, static_cast<std::size_t>(output.length + 1), &usedEnd)) return Reason::PreparedMalformed;
        // Allocated capacity can legitimately exceed the accepted payload limit.
        // Only safe arithmetic and the bounded used range (including NUL) are
        // required; querying a huge unused capacity would defeat the read bound.
        const auto used = static_cast<std::size_t>(output.length + 1);
        if (output.inImage ? !ImageRange(rva, used) : !PrivateRange(output.data, used))
            return Reason::PreparedUnavailable;
        return Reason::None;
    }
};
} // namespace

const PreparedLayout& ProductionPreparedLayout() noexcept { return kProductionLayout; }

Reason ReadPreparedState(const PreparedReadContext& context, const NativeCounts& expected,
    char* scratch, std::size_t scratchCapacity, PreparedSnapshot* output) noexcept {
    const Scrubber scrub{scratch, scratchCapacity < kJsonBytes ? scratchCapacity : kJsonBytes};
    if (output) *output = {};
    if (!scratch || !output) return Reason::PreparedUnavailable;
    if (scratchCapacity != kJsonBytes) return Reason::PreparedLimit;
    if (!context.memory.query || !context.memory.read || !context.hostBase || !context.hostImageSize ||
        context.hostImageSize > (std::numeric_limits<std::uintptr_t>::max)() - context.hostBase)
        return Reason::PreparedUnavailable;
    const auto& layout = context.layout ? *context.layout : kProductionLayout;
    const auto fits = [&context](std::uint32_t rva, std::size_t size) noexcept {
        return rva && rva < context.hostImageSize && size <= context.hostImageSize - rva;
    };
    if (!fits(layout.service,4) || !fits(layout.registration,32) || !fits(layout.gameMode,32) ||
        !fits(layout.maximum,4) || !fits(layout.members,24) || !fits(layout.publicIp,16) ||
        !fits(layout.fullDirty,1)) return Reason::PreparedUnavailable;
    ReadScope scope(context.memory);
    auto scopedContext=context;
    scopedContext.memory=scope.Ops();
    ImageSections sections(context.hostBase,context.hostImageSize,scope.Ops());
    const PreparedReader reader(scopedContext,sections);
    Headers before{}, after{};
    auto reason = reader.ReadHeaders(before);
    if (reason != Reason::None) return reason;
    bool mismatch = before.maximum != expected.maximum || before.membersCount != expected.pi;
    if (!reader.Copy(before.gameMode, scratch)) return Reason::PreparedUnavailable;
    reason = ValidatePreparedJson(scratch, static_cast<std::size_t>(before.gameMode.length), expected);
    if (reason != Reason::None && reason != Reason::PreparedMismatch) return reason;
    mismatch = mismatch || reason == Reason::PreparedMismatch;
    scope.Reset(); // The second live-header/protection observation gets no first-pass query answers.
    sections.Reset();
    reason = reader.ReadHeaders(after);
    if (reason != Reason::None) return reason;
    // Observe may accept stable, structurally valid stale numbers. It must not
    // confuse an unparsed JSON body or a changing header/lifetime with that case.
    if (!SameHeaders(before, after)) return Reason::PreparedUnavailable;
    if (mismatch) return Reason::PreparedMismatch;
    output->counts = expected;
    output->membersCount = before.membersCount;
    output->jsonBytes = static_cast<std::uint32_t>(before.gameMode.length);
    return Reason::None;
}
} // namespace rs2fix::reporting

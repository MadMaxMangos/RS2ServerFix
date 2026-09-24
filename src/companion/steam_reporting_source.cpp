#include "companion/steam_reporting_source.h"
#include "companion/steam_reporting_read_scope.h"

#include <cmath>
#include <limits>

namespace rs2fix::reporting {
namespace {
constexpr SourceLayout kProductionLayout{0x17950C8, 0x1783E80, 0x17981A0, 0x17986E0};
constexpr std::uint64_t kPendingKill = 1ULL << 61;

// Small same-object scalar windows only. Reads remain guarded and independent
// between passes; one RPM transfer is not claimed to be an atomic snapshot.
// Intervening UObject/Game bytes and wrapper padding are ignored: they never
// contribute to admission, snapshots, records, or status.
// DWORD chunks keep the native unaligned flags at +0C and the whole transfer
// exactly 20 bytes, without packed members or trailing pointer-alignment bytes.
struct ObjectFields {
    std::uint32_t tableLow,tableHigh;
    std::uint32_t ignored08;
    std::uint32_t flagsLow,flagsHigh;
};
struct ArrayFields { std::uintptr_t data; std::int32_t count; std::int32_t capacity; };
struct GameFields {
    std::int32_t spectators,maximum;
    std::uint32_t ignored2E8;
    std::int32_t humans,bots;
};
struct OuterFields {
    std::int32_t bots,count,maximum;
    std::uint8_t requested,dirty;
    std::uint16_t ignoredA2;
    float timer;
};
static_assert(sizeof(std::uintptr_t)==8 && sizeof(ObjectFields)==20 &&
    offsetof(ObjectFields,tableHigh)==4 && offsetof(ObjectFields,ignored08)==8 &&
    offsetof(ObjectFields,flagsLow)==0x0C && offsetof(ObjectFields,flagsHigh)==0x10);
static_assert(sizeof(ArrayFields)==16 && offsetof(ArrayFields,count)==8 && offsetof(ArrayFields,capacity)==12);
static_assert(sizeof(GameFields)==20 && offsetof(GameFields,maximum)==4 &&
    offsetof(GameFields,ignored2E8)==8 && offsetof(GameFields,humans)==12 && offsetof(GameFields,bots)==16);
static_assert(sizeof(OuterFields)==20 && offsetof(OuterFields,count)==4 && offsetof(OuterFields,maximum)==8 &&
    offsetof(OuterFields,requested)==12 && offsetof(OuterFields,dirty)==13 &&
    offsetof(OuterFields,ignoredA2)==14 && offsetof(OuterFields,timer)==16);
static_assert(std::is_trivial_v<ObjectFields> && std::is_trivial_v<ArrayFields> &&
    std::is_trivial_v<GameFields> && std::is_trivial_v<OuterFields>);
static_assert(std::is_standard_layout_v<ObjectFields> && std::is_standard_layout_v<ArrayFields> && std::is_standard_layout_v<GameFields> &&
    std::is_standard_layout_v<OuterFields>);

bool Add(std::uintptr_t base, std::size_t offset, std::uintptr_t* result) noexcept {
    if (!base || offset > (std::numeric_limits<std::uintptr_t>::max)() - base) return false;
    *result = base + offset;
    return true;
}
bool FiniteTimer(float value) noexcept { return std::isfinite(value) && value >= 0; }

class SourceReader {
public:
    SourceReader(const SourceReadContext& context,ImageSections& sections) noexcept : context_(context),sections_(sections) {}

    Reason Read(SourceSnapshot& output) const noexcept {
        output = {};
        auto& id = output.identity;
        const auto& layout = context_.layout ? *context_.layout : kProductionLayout;
        id.lifecycle = context_.lifecycle;
        if (!Global(layout.world, id.world) || !Global(layout.worldInfoClass, id.expectedWorldInfoClass))
            return Reason::SourceUnavailable;
        auto reason = Object(id.world, false, id.vtables[0]);
        if (reason != Reason::None) return reason;
        if (!Field(id.world, 0x80, id.level)) return Reason::SourceUnavailable;
        reason = Object(id.level, false, id.vtables[1]);
        if (reason != Reason::None) return reason;

        ArrayFields actors{};
        if (!Field(id.level, 0x60, actors)) return Reason::SourceUnavailable;
        id.actors=actors.data;
        if (actors.count <= 0 || actors.capacity < actors.count ||
            actors.capacity > static_cast<std::int32_t>(kSourceActorCapacity) ||
            !Aligned(id.actors, alignof(std::uintptr_t)) ||
            !HeapRange(id.actors, static_cast<std::size_t>(actors.capacity) * sizeof(std::uintptr_t)) ||
            !HeapRead(id.actors, &id.worldInfo, sizeof(id.worldInfo))) return Reason::SourceUnavailable;
        // Only element zero is read. No player/actor enumeration is performed.
        reason = Object(id.worldInfo, true, id.vtables[2]);
        if (reason != Reason::None) return reason;
        reason = ClassChain(id);
        if (reason != Reason::None) return reason;
        if (!Field(id.worldInfo, 0x5CC, id.game)) return Reason::SourceUnavailable;
        reason = Object(id.game, true, id.vtables[3]);
        if (reason != Reason::None) return reason;
        // 966DE0 proves WorldInfo's cached-class ancestry. It does not prove a
        // GameInfo class cache; Game follows the native qualified WorldInfo field.

        std::uint32_t begun{};
        std::uint8_t netMode{};
        if (!Field(id.worldInfo, 0x398, begun) || !Field(id.worldInfo, 0x598, netMode) ||
            !Field(id.worldInfo, 0x4FC, output.realTimeSeconds)) return Reason::SourceUnavailable;
        if (!(begun & 0x100U) || netMode != 1 || !FiniteTimer(output.realTimeSeconds))
            return Reason::WorldNotReady;
        reason = Travel(id.worldInfo);
        if (reason != Reason::None) return reason;

        GameFields game{};
        if (!Field(id.game, 0x2E0, game)) return Reason::SourceUnavailable;
        // Human/spectator accounting can drift and is not the advertised count.
        // Bots are staged into the native wrapper: reject B>M here, before the
        // store and the producer's later sticky-fault check. Never clamp H or S.
        if (game.maximum < 0 || game.maximum > 255 || game.humans < 0 ||
            game.bots < 0 || game.bots > game.maximum) return Reason::UnsupportedCounts;
        if (game.spectators > 0) return Reason::SpectatorsPresent;
        output.humans = static_cast<std::uint32_t>(game.humans);
        output.bots = static_cast<std::uint32_t>(game.bots);
        output.maximum = static_cast<std::uint32_t>(game.maximum);

        std::uintptr_t privateWrapper{};
        if (!Global(layout.publicWrapper, id.wrapper) || !Global(layout.privateWrapper, privateWrapper))
            return Reason::SourceUnavailable;
        if (!id.wrapper || id.wrapper != privateWrapper) return Reason::WrapperMismatch;
        if (!Aligned(id.wrapper, alignof(std::uintptr_t)) ||
            !Field(id.wrapper, 0, id.interfaceObject)) return Reason::SourceUnavailable;
        if (!id.interfaceObject || !context_.acceptedInterface(context_.interfaceContext,
            id.interfaceObject, context_.lifecycle)) return Reason::ProxyUnavailable;

        OuterFields outer{};
        if (!Field(id.wrapper, 0x94, outer)) return Reason::SourceUnavailable;
        output.producerTimer=outer.timer;
        if (outer.maximum != game.maximum) return Reason::CapacityMismatch;
        if (outer.bots < 0 || outer.bots > 255 || outer.count < 0 || outer.count > 4096)
            return Reason::UnsupportedCounts;
        if (outer.requested > 1 || outer.dirty > 1 || !FiniteTimer(output.producerTimer)) return Reason::SourceUnavailable;
        output.outer = {static_cast<std::uint32_t>(outer.count), static_cast<std::uint32_t>(outer.bots),
            static_cast<std::uint32_t>(outer.maximum)};
        output.requested = outer.requested != 0;
        output.dirty = outer.dirty != 0;
        return Reason::None;
    }

private:
    const SourceReadContext& context_;
    ImageSections& sections_;

    static bool Aligned(std::uintptr_t address, std::size_t alignment) noexcept {
        return address != 0 && (address & (alignment - 1)) == 0;
    }
    bool HeapRange(std::uintptr_t address, std::size_t size) const noexcept {
        std::uintptr_t end{};
        if (!size || !Add(address, size, &end)) return false;
        auto cursor = address;
        for (std::size_t n = 0; cursor < end && n < kSourceRegionLimit; ++n) {
            MemoryRegion region{};
            DWORD error{};
            if (!context_.memory.query(context_.memory.context, cursor, &region, &error) ||
                region.state != MEM_COMMIT || region.type != MEM_PRIVATE ||
                region.protect != PAGE_READWRITE || !region.allocationBase ||
                region.allocationBase > region.base || region.base > cursor || !region.size ||
                region.size > (std::numeric_limits<std::uintptr_t>::max)() - region.base ||
                region.base + region.size <= cursor) return false;
            const auto next = region.base + region.size;
            cursor = next < end ? next : end;
        }
        return cursor == end;
    }
    bool HeapRead(std::uintptr_t address, void* output, std::size_t size) const noexcept {
        DWORD error{};
        return HeapRange(address, size) &&
            context_.memory.read(context_.memory.context, address, output, size, &error);
    }
    template<class T> bool Field(std::uintptr_t object, std::size_t offset, T& output) const noexcept {
        std::uintptr_t address{};
        return Add(object, offset, &address) && HeapRead(address, &output, sizeof(output));
    }
    template<class T> bool Global(std::uint32_t rva, T& output) const noexcept {
        DWORD error{};
        return sections_.Matches(rva, sizeof(output),
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE,
                IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE) &&
            ImageRangeProtection(context_.hostBase, context_.hostImageSize, rva, sizeof(output),
                PAGE_READWRITE, context_.memory, &error) &&
            ReadImageRange(context_.hostBase, context_.hostImageSize, rva, &output,
                sizeof(output), context_.memory, &error);
    }
    bool Vtable(std::uintptr_t table) const noexcept {
        if (!Aligned(table, alignof(std::uintptr_t)) || table < context_.hostBase ||
            table - context_.hostBase >= context_.hostImageSize) return false;
        const auto rva = static_cast<std::uint32_t>(table - context_.hostBase);
        DWORD error{};
        std::uintptr_t target{};
        if (!sections_.Matches(rva, sizeof(target),
                IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_DISCARDABLE) ||
            !ImageRangeProtection(context_.hostBase, context_.hostImageSize, rva, sizeof(target),
                PAGE_READONLY, context_.memory, &error) ||
            !ReadImageRange(context_.hostBase, context_.hostImageSize, rva, &target, sizeof(target),
                context_.memory, &error) || target < context_.hostBase ||
            target - context_.hostBase >= context_.hostImageSize) return false;
        const auto targetRva = static_cast<std::uint32_t>(target - context_.hostBase);
        return sections_.Matches(targetRva, 1,
                IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE) &&
            ImageRangeProtection(context_.hostBase, context_.hostImageSize, targetRva, 1,
                PAGE_EXECUTE_READ, context_.memory, &error);
    }
    Reason Object(std::uintptr_t object, bool actor, std::uintptr_t& table) const noexcept {
        ObjectFields fields{};
        if (!Aligned(object, alignof(std::uintptr_t)) || !Field(object, 0, fields))
            return Reason::SourceUnavailable;
        // The qualified host is AMD64 little-endian. Decode only a complete
        // guarded transfer; neither half of a failed/partial read is authority.
        table=(static_cast<std::uintptr_t>(fields.tableHigh)<<32)|fields.tableLow;
        const std::uint64_t flags=(static_cast<std::uint64_t>(fields.flagsHigh)<<32)|fields.flagsLow;
        if (flags & kPendingKill) return Reason::SourceLifetime;
        if (!Vtable(table)) return Reason::SourceClass;
        if (actor) {
            std::uint8_t actorFlags{};
            if (!Field(object, 0x60, actorFlags)) return Reason::SourceUnavailable;
            if (actorFlags & 0x20U) return Reason::SourceLifetime;
        }
        return Reason::None;
    }
    Reason ClassChain(SourceIdentity& id) const noexcept {
        if (!id.expectedWorldInfoClass) return Reason::SourceClass;
        std::uintptr_t current{};
        if (!Field(id.worldInfo, 0x50, current)) return Reason::SourceClass;
        for (std::size_t n = 0; n < kSourceClassDepth; ++n) {
            if (!current) return Reason::SourceClass;
            for (std::size_t j = 0; j < n; ++j)
                if (id.classChain[j] == current) return Reason::SourceClass;
            std::uintptr_t table{};
            if (Object(current, false, table) != Reason::None) return Reason::SourceClass;
            id.classChain[n] = current;
            ++id.classCount;
            if (current == id.expectedWorldInfoClass) return Reason::None;
            if (!Field(current, 0x78, current)) return Reason::SourceClass;
        }
        return Reason::SourceClass;
    }
    Reason Travel(std::uintptr_t worldInfo) const noexcept {
        ArrayFields travel{};
        if (!Field(worldInfo, 0x624, travel) || travel.count < 0 || travel.capacity < travel.count ||
            travel.capacity > static_cast<std::int32_t>(kSourceTravelCapacity)) return Reason::SourceUnavailable;
        if (!travel.capacity) {
            if (travel.data || travel.count) return Reason::SourceUnavailable;
        } else if (!Aligned(travel.data, sizeof(std::uint16_t)) ||
            !HeapRange(travel.data, static_cast<std::size_t>(travel.capacity) * sizeof(std::uint16_t)))
            return Reason::SourceUnavailable;
        // Native pending travel uses a nonzero FString Num. Querying its backing
        // range is allowed, but not even an empty retained buffer is dereferenced.
        return travel.count == 0 ? Reason::None : Reason::Travel;
    }
};

bool EqualSnapshot(const SourceSnapshot& a, const SourceSnapshot& b) noexcept {
    return EqualSourceIdentity(a.identity, b.identity) && a.humans == b.humans &&
        a.bots == b.bots && a.maximum == b.maximum && EqualCounts(a.outer, b.outer) &&
        a.realTimeSeconds == b.realTimeSeconds && a.producerTimer == b.producerTimer &&
        a.requested == b.requested && a.dirty == b.dirty;
}
} // namespace

bool EqualSourceIdentity(const SourceIdentity& a, const SourceIdentity& b) noexcept {
    if (a.world != b.world || a.level != b.level || a.actors != b.actors ||
        a.worldInfo != b.worldInfo || a.game != b.game ||
        a.expectedWorldInfoClass != b.expectedWorldInfoClass || a.wrapper != b.wrapper ||
        a.interfaceObject != b.interfaceObject || a.lifecycle != b.lifecycle ||
        a.classCount != b.classCount || a.classCount > kSourceClassDepth) return false;
    for (std::size_t i = 0; i < 4; ++i) if (a.vtables[i] != b.vtables[i]) return false;
    for (std::size_t i = 0; i < a.classCount; ++i)
        if (a.classChain[i] != b.classChain[i]) return false;
    return true;
}
const SourceLayout& ProductionSourceLayout() noexcept { return kProductionLayout; }

Reason ReadSourceSnapshot(const SourceReadContext& context, SourceSnapshot* output) noexcept {
    if (!output) return Reason::SourceUnavailable;
    *output = {};
    if (!context.memory.query || !context.memory.read || !context.acceptedInterface ||
        !context.hostBase || !context.hostImageSize ||
        context.hostImageSize > (std::numeric_limits<std::uintptr_t>::max)() - context.hostBase)
        return Reason::SourceUnavailable;
    ReadScope scope(context.memory);
    auto scopedContext=context;
    scopedContext.memory=scope.Ops();
    ImageSections sections(context.hostBase,context.hostImageSize,scope.Ops());
    const SourceReader reader(scopedContext,sections);
    SourceSnapshot before{}, after{};
    auto reason = reader.Read(before);
    if (reason != Reason::None) return reason;
    scope.Reset(); // Re-query identity/protection independently; never cache across the two passes.
    sections.Reset();
    reason = reader.Read(after);
    if (reason != Reason::None) return reason;
    if (!EqualSnapshot(before, after)) return Reason::SourceLifetime;
    *output = after;
    return Reason::None;
}
} // namespace rs2fix::reporting

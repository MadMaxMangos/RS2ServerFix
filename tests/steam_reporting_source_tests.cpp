#include "companion/steam_reporting_source.h"
#include "companion/steam_reporting_prepared.h"
#include "companion/steam_reporting_read_scope.h"
#include "test_framework.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <vector>

namespace {
using namespace rs2fix;
using namespace rs2fix::reporting;
constexpr std::uintptr_t kHost = 0x140000000ULL;
constexpr std::uint32_t kImageSize = 0x1800000;
constexpr std::uintptr_t kWorld = 0x200000000ULL;
constexpr std::uintptr_t kLevel = kWorld + 0x10000;
constexpr std::uintptr_t kActors = kWorld + 0x20000;
constexpr std::uintptr_t kInfo = kWorld + 0x30000;
constexpr std::uintptr_t kGame = kWorld + 0x40000;
constexpr std::uintptr_t kClasses = kWorld + 0x50000;
constexpr std::uintptr_t kWrapper = kWorld + 0x60000;
constexpr std::uintptr_t kTravel = kWorld + 0x70000;
constexpr std::uintptr_t kInterface = kWorld + 0x80000;
constexpr std::uintptr_t kVtable = kHost + 0x2100;
constexpr std::uint64_t kLifecycle = 1ULL << 32;

struct Segment {
    MemoryRegion region;
    std::vector<unsigned char> bytes;
};
struct Fixture {
    std::vector<Segment> segments;
    std::uintptr_t failRead{};
    std::uintptr_t failQuery{};
    bool rejectInterface{};
    bool readOtherActor{};
    bool readTravel{};
    unsigned interfaceCalls{};
    unsigned mutateOnInterface{};
    unsigned mutation{};
    unsigned queryCalls{},readCalls{};
    std::uintptr_t changeProtectionAfterRead{};
    std::uintptr_t changedRegion{};
    bool invalidateHeaderAfterRead{};
    bool partialReadFault{},tornOuter{},tornObjectHeader{};
    std::size_t partialReadBytes{3};

    Fixture() {
        Add(kHost, 0x1000, MEM_IMAGE, PAGE_READONLY, kHost);
        Add(kHost + 0x1000, 0x1000, MEM_IMAGE, PAGE_EXECUTE_READ, kHost);
        Add(kHost + 0x2000, 0x1000, MEM_IMAGE, PAGE_READONLY, kHost);
        Add(kHost + 0x1700000, 0x100000, MEM_IMAGE, PAGE_READWRITE, kHost);
        for (const auto address : {kWorld, kLevel, kActors, kInfo, kGame, kWrapper, kTravel})
            Add(address, 0x1000, MEM_PRIVATE, PAGE_READWRITE, address);
        Add(kClasses, 0x5000, MEM_PRIVATE, PAGE_READWRITE, kClasses);
        IMAGE_DOS_HEADER dos{};
        dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80;
        Put(kHost, dos);
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 3;
        nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage = kImageSize;
        nt.OptionalHeader.SizeOfHeaders = 0x400;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        Put(kHost + 0x80, nt);
        for (unsigned n = 0; n < 3; ++n) {
            IMAGE_SECTION_HEADER section{};
            section.VirtualAddress = n == 2 ? 0x1700000 : 0x1000 * (n + 1);
            section.Misc.VirtualSize = n == 2 ? 0x100000 : 0x1000;
            section.Characteristics = IMAGE_SCN_MEM_READ |
                (n == 0 ? IMAGE_SCN_MEM_EXECUTE : n == 2 ? IMAGE_SCN_MEM_WRITE : 0);
            Put(kHost + 0x80 + sizeof(nt) + n * sizeof(section), section);
        }
        Put(kVtable, kHost + 0x1000);
        for (const auto object : {kWorld, kLevel, kInfo, kGame, kClasses, kClasses + 0x100})
            Put(object, kVtable);
        Put(kHost + 0x17950C8, kWorld);
        Put(kHost + 0x1783E80, kClasses + 0x100);
        Put(kWorld + 0x80, kLevel);
        Put(kLevel + 0x60, kActors);
        Put(kLevel + 0x68, std::int32_t{64});
        Put(kLevel + 0x6C, std::int32_t{128});
        Put(kActors, kInfo);
        Put(kInfo + 0x50, kClasses);
        Put(kClasses + 0x78, kClasses + 0x100);
        Put(kInfo + 0x5CC, kGame);
        Put(kInfo + 0x398, std::uint32_t{0x100});
        Put(kInfo + 0x598, std::uint8_t{1});
        Put(kInfo + 0x4FC, 1234.0F);
        Put(kGame + 0x2E0, std::int32_t{0});
        Put(kGame + 0x2E4, std::int32_t{64});
        Put(kGame + 0x2EC, std::int32_t{40});
        Put(kGame + 0x2F0, std::int32_t{24});
        Put(kHost + 0x17981A0, kWrapper);
        Put(kHost + 0x17986E0, kWrapper);
        Put(kWrapper, kInterface);
        Put(kWrapper + 0x94, std::int32_t{24});
        Put(kWrapper + 0x98, std::int32_t{65});
        Put(kWrapper + 0x9C, std::int32_t{64});
        Put(kWrapper + 0xA0, std::uint8_t{1});
        Put(kWrapper + 0xA1, std::uint8_t{1});
        Put(kWrapper + 0xA4, 7.0F);
    }
    void Add(std::uintptr_t base, std::size_t size, DWORD type, DWORD protection, std::uintptr_t allocation) {
        segments.push_back({{base, allocation, size, MEM_COMMIT, type, protection},
            std::vector<unsigned char>(size)});
    }
    Segment* Find(std::uintptr_t address) noexcept {
        for (auto& segment : segments)
            if (address >= segment.region.base && address - segment.region.base < segment.bytes.size()) return &segment;
        return nullptr;
    }
    template<class T> void Put(std::uintptr_t address, const T& value) {
        auto* segment = Find(address);
        if (!segment || sizeof(value) > segment->bytes.size() - (address - segment->region.base)) {
            RS2_CHECK(false); return;
        }
        std::memcpy(segment->bytes.data() + address - segment->region.base, &value, sizeof(value));
    }
    static bool Query(void* context, std::uintptr_t address, MemoryRegion* output, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.queryCalls;
        auto* segment = f.Find(address);
        if (!segment || address == f.failQuery) { *error = ERROR_NOACCESS; return false; }
        *output = segment->region;
        *error = ERROR_SUCCESS;
        return true;
    }
    static bool Read(void* context, std::uintptr_t address, void* output, std::size_t size, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.readCalls;
        if (address >= kActors + sizeof(std::uintptr_t) && address < kActors + 0x1000) f.readOtherActor = true;
        if (address >= kTravel && address < kTravel + 0x1000) f.readTravel = true;
        auto* segment = f.Find(address);
        if (!segment || size > segment->bytes.size() - (address - segment->region.base)) {
            *error = ERROR_PARTIAL_COPY; return false;
        }
        if (f.failRead>=address && f.failRead-address<size) {
            if (f.partialReadFault) std::memcpy(output,segment->bytes.data()+address-segment->region.base,
                (std::min)(size,f.partialReadBytes));
            *error=ERROR_PARTIAL_COPY; return false;
        }
        std::memcpy(output, segment->bytes.data() + address - segment->region.base, size);
        if (f.tornObjectHeader && address==kInfo && size==20) {
            const std::uintptr_t olderTable=kVtable+8;
            std::memcpy(output,&olderTable,sizeof(olderTable));
            f.tornObjectHeader=false; // The independent second observation sees the current vptr.
        }
        if (f.tornOuter && address==kWrapper+0x94 && size==20) {
            const std::int32_t olderCount=64;
            std::memcpy(static_cast<unsigned char*>(output)+4,&olderCount,sizeof(olderCount));
            f.tornOuter=false; // Next independent observation sees the actual 65.
        }
        if (address==f.changeProtectionAfterRead) {
            if (f.invalidateHeaderAfterRead) f.Put(kHost,std::uint16_t{0});
            else f.Find(f.changedRegion)->region.protect=PAGE_READONLY;
            f.changeProtectionAfterRead=0;
        }
        *error = ERROR_SUCCESS;
        return true;
    }
    static bool Accepted(void* context, std::uintptr_t object, std::uint64_t lifecycle) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        ++f.interfaceCalls;
        if (f.mutateOnInterface == f.interfaceCalls) {
            if (f.mutation == 0) f.Put(kInfo + 0x398, std::uint32_t{0});
            else if (f.mutation == 1) f.Put(kGame + 0x2EC, std::int32_t{39});
            else if (f.mutation == 2) {
                f.Put(kGame + 0x2E4, std::int32_t{63});
                f.Put(kWrapper + 0x9C, std::int32_t{63});
                f.Put(kGame + 0x2EC, std::int32_t{39});
            } else if (f.mutation == 3) f.Put(kHost + 0x17986E0, std::uintptr_t{0});
            else if (f.mutation == 4) f.Put(kClasses + 0x78, std::uintptr_t{0});
            else if (f.mutation == 5) f.Find(kInfo)->region.protect=PAGE_READONLY;
            else if (f.mutation == 6) f.Put(kHost,std::uint16_t{0});
            else if (f.mutation == 7) f.Find(kHost)->region.protect=PAGE_NOACCESS;
            else if (f.mutation == 8) f.Put(kInfo+0x0C,std::uint64_t{1ULL<<61});
            else if (f.mutation == 9) f.Put(kGame+0x2E0,std::int32_t{-3});
            else if (f.mutation == 10) f.Put(kGame+0x2E0,std::int32_t{0});
            else if (f.mutation == 11) f.Put(kGame+0x2E0,std::int32_t{1});
        }
        return !f.rejectInterface && object == kInterface && lifecycle == kLifecycle;
    }
    SourceReadContext Context() noexcept {
        return {{this, Query, Read}, kHost, kImageSize, kLifecycle, this, Accepted};
    }
    Reason Run(SourceSnapshot* output = nullptr) {
        SourceSnapshot local{};
        return ReadSourceSnapshot(Context(), output ? output : &local);
    }
};

void QualifiedSnapshot() {
    Fixture f;
    f.Put(kGame+0x2E8,UINT32_MAX); f.Put(kWrapper+0xA2,std::uint16_t{UINT16_MAX});
    for (const auto object:{kWorld,kLevel,kInfo,kGame,kClasses,kClasses+0x100})
        f.Put(object+8,UINT32_MAX); // Intervening header bytes are not pointer/flags bits.
    SourceSnapshot snapshot{};
    RS2_CHECK(f.Run(&snapshot) == Reason::None);
    RS2_CHECK(snapshot.humans == 40 && snapshot.bots == 24 && snapshot.maximum == 64);
    RS2_CHECK(snapshot.outer.pi == 65 && snapshot.outer.maximum == 64);
    RS2_CHECK(snapshot.requested && snapshot.dirty && snapshot.producerTimer == 7.0F);
    RS2_CHECK(snapshot.realTimeSeconds == 1234.0F && snapshot.identity.classCount == 2);
    RS2_CHECK(snapshot.identity.world == kWorld && snapshot.identity.level == kLevel &&
        snapshot.identity.worldInfo == kInfo && snapshot.identity.game == kGame &&
        snapshot.identity.wrapper == kWrapper && snapshot.identity.interfaceObject == kInterface);
    RS2_CHECK(f.interfaceCalls == 2 && !f.readOtherActor && !f.readTravel);
    // Stale cached bots are valid observations, not permission to claim a new
    // producer witness. Native PI_COUNT has no enforced humans+bots equation.
    f.Put(kWrapper + 0x94, std::int32_t{21});
    f.Put(kWrapper + 0x98, std::int32_t{62});
    RS2_CHECK(f.Run(&snapshot) == Reason::None && snapshot.outer.bots == 21);
    f.Put(kInfo + 0x624, kTravel);
    f.Put(kInfo + 0x630, std::int32_t{128});
    RS2_CHECK(f.Run() == Reason::None && !f.readTravel);
    f.Put(kInfo + 0x62C, std::int32_t{1});
    RS2_CHECK(f.Run() == Reason::Travel && !f.readTravel);
}
void StructuralAndLifetimeGuards() {
    for (const auto address : {kHost + 0x17950C8, kWorld + 0x80, kLevel + 0x60, kActors, kInfo + 0x5CC}) {
        Fixture f;
        f.Put(address, std::uintptr_t{0});
        SourceSnapshot output{}; output.humans = 123;
        RS2_CHECK(f.Run(&output) != Reason::None && output.humans == 0 && output.identity.world == 0);
    }
    for (const auto address : {kWorld, kLevel, kInfo, kGame}) {
        Fixture f;
        f.Put(address + 0x0C, std::uint64_t{1ULL << 61});
        RS2_CHECK(f.Run() == Reason::SourceLifetime);
    }
    for (const auto address : {kInfo, kGame}) {
        Fixture f;
        f.Put(address + 0x60, std::uint8_t{0x20});
        RS2_CHECK(f.Run() == Reason::SourceLifetime);
    }
    for (const auto count : {std::int32_t{-1}, std::int32_t{0}, std::int32_t{129}}) {
        Fixture f;
        f.Put(kLevel + 0x68, count);
        RS2_CHECK(f.Run() == Reason::SourceUnavailable);
    }
    { Fixture f; f.Put(kLevel + 0x6C, std::int32_t{kSourceActorCapacity + 1});
      RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    { Fixture f; f.Put(kLevel + 0x60, (std::numeric_limits<std::uintptr_t>::max)() - 7);
      RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    { Fixture f; f.Put(kInfo + 0x624, kTravel); f.Put(kInfo + 0x62C, std::int32_t{2});
      f.Put(kInfo + 0x630, std::int32_t{1}); RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    { Fixture f; f.Put(kInfo + 0x630, std::int32_t{kSourceTravelCapacity + 1});
      RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    { Fixture f; f.Put(kInfo + 0x624, kTravel); RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    { Fixture f; f.Put(kInfo + 0x630, std::int32_t{4}); RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    { Fixture f; f.Put(kHost + 0x17981A0, std::uintptr_t{0}); RS2_CHECK(f.Run() == Reason::WrapperMismatch); }
    { Fixture f; f.Put(kHost + 0x17986E0, kWrapper + 8); RS2_CHECK(f.Run() == Reason::WrapperMismatch); }
    { Fixture f; f.rejectInterface = true; RS2_CHECK(f.Run() == Reason::ProxyUnavailable); }
    { Fixture f; f.Put(kWrapper, kInterface + 8); RS2_CHECK(f.Run() == Reason::ProxyUnavailable); }
    { Fixture f; auto context = f.Context(); context.lifecycle += 1ULL << 32;
      SourceSnapshot output{}; RS2_CHECK(ReadSourceSnapshot(context, &output) == Reason::ProxyUnavailable); }
}
void ReadinessAndCounts() {
    { Fixture f; f.Put(kInfo + 0x398, std::uint32_t{0}); RS2_CHECK(f.Run() == Reason::WorldNotReady); }
    for (const auto mode : {std::uint8_t{0}, std::uint8_t{2}, std::uint8_t{255}}) {
        Fixture f; f.Put(kInfo + 0x598, mode); RS2_CHECK(f.Run() == Reason::WorldNotReady);
    }
    for (const auto time : {-1.0F, (std::numeric_limits<float>::infinity)(),
        (std::numeric_limits<float>::quiet_NaN)()}) {
        Fixture f; f.Put(kInfo + 0x4FC, time); RS2_CHECK(f.Run() == Reason::WorldNotReady);
        Fixture g; g.Put(kWrapper + 0xA4, time); RS2_CHECK(g.Run() == Reason::SourceUnavailable);
    }
    { Fixture f; f.Put(kGame + 0x2E0, std::int32_t{1}); RS2_CHECK(f.Run() == Reason::SpectatorsPresent); }
    { Fixture f; f.Put(kWrapper + 0x9C, std::int32_t{63}); RS2_CHECK(f.Run() == Reason::CapacityMismatch); }
    for (const auto address : {kGame + 0x2E4, kGame + 0x2EC, kGame + 0x2F0,
        kWrapper + 0x94, kWrapper + 0x98}) {
        Fixture f; f.Put(address, std::int32_t{-1}); RS2_CHECK(f.Run() == Reason::UnsupportedCounts);
    }
    { Fixture f; f.Put(kGame + 0x2E4, std::int32_t{256}); RS2_CHECK(f.Run() == Reason::UnsupportedCounts); }
    { Fixture f; f.Put(kGame + 0x2EC, INT32_MAX); f.Put(kGame + 0x2F0, INT32_MAX);
      RS2_CHECK(f.Run() == Reason::UnsupportedCounts); }
    { Fixture f; f.Put(kWrapper + 0x98, std::int32_t{4097}); RS2_CHECK(f.Run() == Reason::UnsupportedCounts); }
    for (const auto field : {kWrapper + 0xA0, kWrapper + 0xA1}) {
        Fixture f; f.Put(field, std::uint8_t{2}); RS2_CHECK(f.Run() == Reason::SourceUnavailable);
    }
}
void DiagnosticCountDrift() {
    struct Case {
        std::int32_t spectators, humans, bots, maximum, pi;
        Reason expected;
    };
    const Case cases[]{
        {-1,63,0,64,62,Reason::None}, {-2,64,0,64,63,Reason::None},
        {-3,65,0,64,63,Reason::None}, {0,65,0,64,63,Reason::None},
        {0,41,24,64,63,Reason::None}, {0,0,64,64,64,Reason::None},
        {0,0,65,64,64,Reason::UnsupportedCounts}, {0,1,0,0,1,Reason::None},
        {INT32_MIN,INT32_MAX,0,64,63,Reason::None}
    };
    for (const auto& test:cases) {
        Fixture f;
        f.Put(kGame+0x2E0,test.spectators); f.Put(kGame+0x2EC,test.humans);
        f.Put(kGame+0x2F0,test.bots); f.Put(kGame+0x2E4,test.maximum);
        f.Put(kWrapper+0x94,test.bots); f.Put(kWrapper+0x98,test.pi);
        f.Put(kWrapper+0x9C,test.maximum);
        SourceSnapshot output{}; output.humans=777;
        RS2_CHECK(f.Run(&output)==test.expected);
        if (test.expected==Reason::None) {
            // PI is independent native input, never reconstructed from H/S/B.
            RS2_CHECK(output.humans==static_cast<std::uint32_t>(test.humans) &&
                output.bots==static_cast<std::uint32_t>(test.bots) &&
                output.maximum==static_cast<std::uint32_t>(test.maximum) &&
                output.outer.pi==static_cast<std::uint32_t>(test.pi));
            RS2_CHECK(f.interfaceCalls==2);
        } else {
            RS2_CHECK(output.humans==0 && output.identity.world==0 && f.interfaceCalls==0);
        }
    }
}
void DriftBetweenSourcePasses() {
    for (const unsigned mutation:{9U,10U,11U,1U}) {
        Fixture f;
        f.Put(kGame+0x2E0,std::int32_t{-1}); f.Put(kGame+0x2EC,std::int32_t{65});
        f.Put(kGame+0x2F0,std::int32_t{0});
        f.Put(kWrapper+0x94,std::int32_t{0}); f.Put(kWrapper+0x98,std::int32_t{63});
        // Accepted runs after the Game read: mutate only after pass one's fields.
        f.mutateOnInterface=1; f.mutation=mutation;
        const auto expected=mutation==11 ? Reason::SpectatorsPresent :
            mutation==1 ? Reason::SourceLifetime : Reason::None;
        SourceSnapshot output{}; output.humans=777;
        RS2_CHECK(f.Run(&output)==expected);
        RS2_CHECK(f.interfaceCalls==(mutation==11 ? 1U : 2U));
        if (expected==Reason::None) {
            RS2_CHECK(output.humans==65 && output.bots==0 && output.outer.pi==63);
        } else {
            RS2_CHECK(output.humans==0 && output.identity.world==0);
        }
    }
}
void ClassAndProtectionGuards() {
    { Fixture f; f.Put(kHost + 0x1783E80, std::uintptr_t{0}); RS2_CHECK(f.Run() == Reason::SourceClass); }
    { Fixture f; f.Put(kInfo + 0x50, std::uintptr_t{0}); RS2_CHECK(f.Run() == Reason::SourceClass); }
    { Fixture f; f.Put(kClasses + 0x78, kClasses); RS2_CHECK(f.Run() == Reason::SourceClass); }
    { Fixture f; f.Put(kClasses + 0x78, std::uintptr_t{0}); RS2_CHECK(f.Run() == Reason::SourceClass); }
    { Fixture f; f.Put(kInfo, kHost + 0x1000); RS2_CHECK(f.Run() == Reason::SourceClass); }
    { Fixture f; f.Put(kVtable, kHost + 0x2100); RS2_CHECK(f.Run() == Reason::SourceClass); }
    { Fixture f; f.Put(kInfo, kHost + kImageSize); RS2_CHECK(f.Run() == Reason::SourceClass); }
    { Fixture f; f.Put(kInfo, kVtable + 1); RS2_CHECK(f.Run() == Reason::SourceClass); }
    for (const auto protection : {DWORD{PAGE_READONLY}, DWORD{PAGE_WRITECOPY}, DWORD{PAGE_NOACCESS},
        DWORD{PAGE_READWRITE | PAGE_GUARD}, DWORD{PAGE_EXECUTE_READWRITE}}) {
        Fixture f; f.Find(kInfo)->region.protect = protection;
        RS2_CHECK(f.Run() == Reason::SourceUnavailable);
    }
    { Fixture f; f.Find(kInfo)->region.type = MEM_MAPPED; RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    { Fixture f; f.Find(kInfo)->region.state = MEM_RESERVE; RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    { Fixture f; f.Find(kHost + 0x17950C8)->region.allocationBase = kWorld;
      RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    { Fixture f; f.failRead = kInfo + 0x5CC; RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    // A failed first query for the region is not cached. Interior re-queries
    // within a successful pass are deliberately coalesced by ReadScope.
    { Fixture f; f.failQuery = kInfo; RS2_CHECK(f.Run() == Reason::SourceUnavailable); }
    for (const auto count : {kSourceClassDepth, kSourceClassDepth + 1}) {
        Fixture f;
        for (std::size_t i = 0; i < count; ++i) {
            f.Put(kClasses + i * 0x100, kVtable);
            f.Put(kClasses + i * 0x100 + 0x78, i + 1 < count ? kClasses + (i + 1) * 0x100 : 0);
        }
        f.Put(kHost + 0x1783E80, kClasses + (count - 1) * 0x100);
        RS2_CHECK(f.Run() == (count == kSourceClassDepth ? Reason::None : Reason::SourceClass));
    }
}
void ReobservationAndIdentity() {
    const Reason expected[]{Reason::WorldNotReady, Reason::SourceLifetime,
        Reason::CapacityMismatch, Reason::WrapperMismatch, Reason::SourceClass,Reason::SourceUnavailable,
        Reason::SourceUnavailable,Reason::SourceUnavailable,Reason::SourceLifetime};
    for (unsigned mutation = 0; mutation < std::size(expected); ++mutation) {
        Fixture f; f.mutateOnInterface = 1; f.mutation = mutation;
        RS2_CHECK(f.Run() == expected[mutation]);
    }
    Fixture f;
    SourceSnapshot a{};
    RS2_CHECK(f.Run(&a) == Reason::None);
    auto b = a;
    RS2_CHECK(EqualSourceIdentity(a.identity, b.identity));
    b.identity.game += 8;
    RS2_CHECK(!EqualSourceIdentity(a.identity, b.identity));
    b = a; b.identity.classChain[0] += 8;
    RS2_CHECK(!EqualSourceIdentity(a.identity, b.identity));
    b = a; b.identity.lifecycle += 1ULL << 32;
    RS2_CHECK(!EqualSourceIdentity(a.identity, b.identity));
    b = a; b.identity.classCount = static_cast<std::uint32_t>(kSourceClassDepth + 1);
    RS2_CHECK(!EqualSourceIdentity(a.identity, b.identity));
    auto context = f.Context();
    context.hostBase = (std::numeric_limits<std::uintptr_t>::max)() - 10;
    RS2_CHECK(ReadSourceSnapshot(context, &b) == Reason::SourceUnavailable);
    context = f.Context(); context.acceptedInterface = nullptr;
    RS2_CHECK(ReadSourceSnapshot(context, &b) == Reason::SourceUnavailable);
    RS2_CHECK(ReadSourceSnapshot(f.Context(), nullptr) == Reason::SourceUnavailable);
}
void GroupedReadFailureAndTear() {
    for (const auto address:{kLevel+0x68,kGame+0x2F0,kWrapper+0xA4,kInfo+0x630}) {
        Fixture f; f.failRead=address; f.partialReadFault=true;
        SourceSnapshot output{}; output.humans=999;
        RS2_CHECK(f.Run(&output)==Reason::SourceUnavailable && output.humans==0 && output.identity.world==0);
        RS2_CHECK(!f.readOtherActor && !f.readTravel);
    }
    Fixture f; f.tornOuter=true;
    SourceSnapshot output{};
    RS2_CHECK(f.Run(&output)==Reason::SourceLifetime && output.identity.wrapper==0 && !f.tornOuter);
}
void ObjectHeaderPartialReadAndTear() {
    {
        Fixture f; f.failRead=kGame+0x10; f.partialReadFault=true; f.partialReadBytes=16;
        SourceSnapshot output{}; output.humans=999;
        // A complete vptr plus only the low flags word must not be salvaged as
        // a valid object when RPM rejects the final part of the header.
        RS2_CHECK(f.Run(&output)==Reason::SourceUnavailable && output.humans==0 && output.identity.world==0);
        RS2_CHECK(!f.readOtherActor && !f.readTravel);
    }
    {
        Fixture f; f.Put(kVtable+8,kHost+0x1000); f.tornObjectHeader=true;
        SourceSnapshot output{};
        // Both individual vptr values qualify. Only independent observations
        // detect this change; a 20-byte transfer is not an atomicity guarantee.
        RS2_CHECK(f.Run(&output)==Reason::SourceLifetime && output.identity.worldInfo==0 && !f.tornObjectHeader);
    }
}
void ScopedQueriesAndFreshReads() {
    Fixture f;
    ReadScope scope(f.Context().memory);
    const auto& ops=scope.Ops();
    MemoryRegion first{},second{}; DWORD error{};
    RS2_CHECK(ops.query(ops.context,kWrapper,&first,&error));
    RS2_CHECK(ops.query(ops.context,kWrapper+0x94,&second,&error) && f.queryCalls==1);
    std::uint32_t bots{};
    RS2_CHECK(ops.read(ops.context,kWrapper+0x94,&bots,sizeof(bots),&error) && bots==24);
    f.Put(kWrapper+0x94,std::uint32_t{23});
    RS2_CHECK(ops.read(ops.context,kWrapper+0x94,&bots,sizeof(bots),&error) && bots==23 && f.readCalls==2);
    f.failRead=kWrapper+0x94;
    RS2_CHECK(!ops.read(ops.context,kWrapper+0x94,&bots,sizeof(bots),&error) && error==ERROR_PARTIAL_COPY);
    f.Find(kWrapper)->region.protect=PAGE_READONLY;
    scope.Reset();
    RS2_CHECK(ops.query(ops.context,kWrapper+0x94,&second,&error) && second.protect==PAGE_READONLY && f.queryCalls==2);

    // Saturation never truncates the caller's region walk or turns a new region
    // into an invented answer. Previously cached regions still work.
    scope.Reset(); f.queryCalls=0;
    constexpr std::uintptr_t base=0x2F0000000ULL;
    for (std::size_t i=0;i<kReadScopeRegions+1;++i) {
        const auto address=base+i*0x1000;
        f.Add(address,0x1000,MEM_PRIVATE,PAGE_READWRITE,address);
        RS2_CHECK(ops.query(ops.context,address,&second,&error));
    }
    RS2_CHECK(f.queryCalls==kReadScopeRegions+1);
    RS2_CHECK(ops.query(ops.context,base+kReadScopeRegions*0x1000+8,&second,&error) && f.queryCalls==kReadScopeRegions+2);
    RS2_CHECK(ops.query(ops.context,base+8,&second,&error) && f.queryCalls==kReadScopeRegions+2);

    // Structurally bad, failed, guarded, and noncommitted replies cannot poison
    // the next query. Their original answer/error remains the reader's input.
    for (unsigned bad=0;bad<7;++bad) {
        Fixture invalid; ReadScope untrusted(invalid.Context().memory);
        auto* region=&invalid.Find(kWrapper)->region;
        const auto saved=*region;
        switch (bad) {
        case 0: region->size=0; break;
        case 1: region->size=(std::numeric_limits<std::uintptr_t>::max)()-region->base+1; break;
        case 2: region->allocationBase=region->base+1; break;
        case 3: region->state=MEM_RESERVE; break;
        case 4: region->type=0; break;
        case 5: region->protect=PAGE_READWRITE|PAGE_GUARD; break;
        case 6: invalid.failQuery=kWrapper; break;
        }
        const auto& queried=untrusted.Ops();
        const bool returned=queried.query(queried.context,kWrapper,&first,&error);
        RS2_CHECK(returned==(bad!=6));
        *region=saved; invalid.failQuery=0;
        RS2_CHECK(queried.query(queried.context,kWrapper,&second,&error) &&
            second.size==saved.size && second.protect==PAGE_READWRITE && invalid.queryCalls==2);
    }
}
void PreparedProtectionRecheck() {
    // Reuse the same fake regions: after GameMode copy, writable global data
    // becomes read-only. The second header pass must query again and reject.
    for (const bool invalidateHeader:{false,true}) {
    Fixture f;
    const PreparedLayout layout{0x1701000,0x1701008,0x1701028,0x1701048,0x1701050,0x1701070,0x1701080};
    f.Put(kHost+layout.service,std::uint32_t{3});
    f.Put(kHost+layout.registration+0x10,std::uint64_t{8});
    f.Put(kHost+layout.registration+0x18,std::uint64_t{15});
    constexpr char json[]="{\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"65\"},{\"k\":\"BotPlayerCount\",\"v\":\"24\"},{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}";
    std::memcpy(f.Find(kWorld)->bytes.data(),json,sizeof(json));
    f.Put(kHost+layout.gameMode,kWorld);
    f.Put(kHost+layout.gameMode+0x10,std::uint64_t{sizeof(json)-1});
    f.Put(kHost+layout.gameMode+0x18,std::uint64_t{4095});
    f.Put(kHost+layout.maximum,std::uint32_t{64});
    f.Put(kHost+layout.members,kActors); f.Put(kHost+layout.members+8,kActors+65*0x20);
    f.Put(kHost+layout.members+16,kActors+128*0x20);
    f.Put(kHost+layout.publicIp,kLevel); f.Put(kHost+layout.publicIp+8,std::int32_t{10});
    f.Put(kHost+layout.publicIp+12,std::int32_t{16}); f.Put(kLevel+18,std::uint16_t{0});
    f.changeProtectionAfterRead=kWorld; f.changedRegion=kHost+layout.service;
    f.invalidateHeaderAfterRead=invalidateHeader;
    const PreparedReadContext context{f.Context().memory,kHost,kImageSize,&layout};
    std::array<char,kJsonBytes> scratch{}; scratch.fill('X'); PreparedSnapshot output{};
    RS2_CHECK(ReadPreparedState(context,{65,24,64},scratch.data(),scratch.size(),&output)==Reason::PreparedUnavailable);
    RS2_CHECK(f.changeProtectionAfterRead==0 && output.jsonBytes==0);
    RS2_CHECK(std::all_of(scratch.begin(),scratch.end(),[](char byte) { return byte==0; }));
    }
}
void ImageSectionValidationAndReset() {
    constexpr std::uint32_t ntRva=0x80;
    constexpr auto tableRva=ntRva+static_cast<std::uint32_t>(sizeof(IMAGE_NT_HEADERS64));
    constexpr std::uint32_t target=0x17950C8;
    constexpr DWORD required=IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;
    constexpr DWORD forbidden=IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_DISCARDABLE;
    for (unsigned bad=0;bad<10;++bad) {
        Fixture f;
        IMAGE_NT_HEADERS64 nt{};
        std::memcpy(&nt,f.Find(kHost)->bytes.data()+ntRva,sizeof(nt));
        IMAGE_SECTION_HEADER section{};
        std::memcpy(&section,f.Find(kHost)->bytes.data()+tableRva,sizeof(section));
        bool expected=false;
        switch (bad) {
        case 0: f.Put(kHost,std::uint16_t{0}); break;
        case 1: f.Put(kHost+offsetof(IMAGE_DOS_HEADER,e_lfanew),std::int32_t{63}); break;
        case 2: nt.FileHeader.Characteristics|=IMAGE_FILE_DLL; f.Put(kHost+ntRva,nt); break;
        case 3: nt.FileHeader.SizeOfOptionalHeader=1; f.Put(kHost+ntRva,nt); break;
        case 4: nt.FileHeader.NumberOfSections=97; f.Put(kHost+ntRva,nt); break;
        case 5: nt.OptionalHeader.SizeOfHeaders=tableRva+3*static_cast<DWORD>(sizeof(section))-1;
            f.Put(kHost+ntRva,nt); break;
        case 6: section.VirtualAddress=kImageSize+1; f.Put(kHost+tableRva,section); break;
        case 7: section.Misc.VirtualSize=kImageSize; f.Put(kHost+tableRva,section); break;
        case 8: // Two sections containing the requested data span are ambiguous.
            std::memcpy(&section,f.Find(kHost)->bytes.data()+tableRva+2*sizeof(section),sizeof(section));
            f.Put(kHost+tableRva+sizeof(section),section); break;
        case 9: // An overlap elsewhere must not widen the shared rejection rule.
            f.Put(kHost+tableRva+sizeof(section),section); expected=true; break;
        }
        const auto ops=f.Context().memory;
        const bool shared=ImageSectionMatches(kHost,kImageSize,target,8,required,forbidden,ops);
        ReadScope scope(ops); ImageSections image(kHost,kImageSize,scope.Ops());
        RS2_CHECK(shared==expected && image.Matches(target,8,required,forbidden)==shared);
    }
    {
        Fixture f; ReadScope scope(f.Context().memory); ImageSections image(kHost,kImageSize,scope.Ops());
        RS2_CHECK(image.Matches(target,8,required,forbidden));
        RS2_CHECK(!image.Matches(target,8,required,IMAGE_SCN_MEM_WRITE));
        RS2_CHECK(!image.Matches(kImageSize-1,2,0,0));
        // Independent pass: previously valid readonly metadata cannot authorize
        // a changed header or newly inaccessible header region.
        f.Put(kHost,std::uint16_t{0}); scope.Reset(); image.Reset();
        RS2_CHECK(!image.Matches(target,8,required,forbidden));
        f.Put(kHost,std::uint16_t{IMAGE_DOS_SIGNATURE}); f.Find(kHost)->region.protect=PAGE_NOACCESS;
        scope.Reset(); image.Reset();
        RS2_CHECK(!image.Matches(target,8,required,forbidden));
    }
    {
        Fixture f; f.Find(kHost)->region.protect=PAGE_READWRITE;
        ReadScope scope(f.Context().memory); ImageSections image(kHost,kImageSize,scope.Ops());
        RS2_CHECK(image.Matches(target,8,required,forbidden));
        // Writable metadata is never remembered even within the same pass.
        f.Put(kHost,std::uint16_t{0});
        RS2_CHECK(!image.Matches(target,8,required,forbidden));
    }
    {
        // Readonly DOS/NT alone are insufficient: a separate writable section
        // table must fall back, and its next mutation must be seen immediately.
        Fixture f;
        IMAGE_NT_HEADERS64 nt{}; std::array<IMAGE_SECTION_HEADER,3> sections{};
        std::memcpy(&nt,f.Find(kHost)->bytes.data()+ntRva,sizeof(nt));
        std::memcpy(sections.data(),f.Find(kHost)->bytes.data()+tableRva,sizeof(sections));
        constexpr std::uint32_t split=0xF00;
        constexpr auto relocatedNt=split-static_cast<std::uint32_t>(sizeof(nt));
        f.Find(kHost)->bytes.resize(split); f.Find(kHost)->region.size=split;
        f.Add(kHost+split,0x1000-split,MEM_IMAGE,PAGE_READWRITE,kHost);
        f.Put(kHost+offsetof(IMAGE_DOS_HEADER,e_lfanew),static_cast<std::int32_t>(relocatedNt));
        nt.OptionalHeader.SizeOfHeaders=0x1000; f.Put(kHost+relocatedNt,nt);
        for (std::size_t i=0;i<sections.size();++i) f.Put(kHost+split+i*sizeof(sections[0]),sections[i]);
        ReadScope scope(f.Context().memory); ImageSections image(kHost,kImageSize,scope.Ops());
        RS2_CHECK(image.Matches(target,8,required,forbidden));
        sections[2].Characteristics=IMAGE_SCN_MEM_READ;
        f.Put(kHost+split+2*sizeof(sections[0]),sections[2]);
        RS2_CHECK(!image.Matches(target,8,required,forbidden));
    }
}
} // namespace

void ReportingSourceTests() {
    QualifiedSnapshot();
    StructuralAndLifetimeGuards();
    ReadinessAndCounts();
    DiagnosticCountDrift();
    DriftBetweenSourcePasses();
    ClassAndProtectionGuards();
    ReobservationAndIdentity();
    GroupedReadFailureAndTear();
    ObjectHeaderPartialReadAndTear();
    ScopedQueriesAndFreshReads();
    PreparedProtectionRecheck();
    ImageSectionValidationAndReset();
}

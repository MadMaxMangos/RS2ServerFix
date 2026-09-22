#include "companion/steam_reporting_prepared.h"
#include "test_framework.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

namespace {
using namespace rs2fix;
using namespace rs2fix::reporting;
constexpr std::uintptr_t kHost = 0x140000000ULL;
constexpr std::uint32_t kImageSize = 0x1800000;
constexpr std::uintptr_t kService = kHost + 0x14AAD20;
constexpr std::uintptr_t kRegistration = kHost + 0x14AAD28;
constexpr std::uintptr_t kGameMode = kHost + 0x14AAD48;
constexpr std::uintptr_t kMaximum = kHost + 0x14AAD68;
constexpr std::uintptr_t kVector = kHost + 0x14AAD70;
constexpr std::uintptr_t kIpHeader = kHost + 0x1798800;
constexpr std::uintptr_t kJson = 0x210000000ULL;
constexpr std::uintptr_t kRegistrationHeap = kJson + 0x20000;
constexpr std::uintptr_t kIp = kJson + 0x30000;
constexpr std::uintptr_t kMemberData = kJson + 0x40000;
constexpr NativeCounts kCounts{65, 24, 64};

std::string Json(std::uint32_t count = 65) {
    return "{\"ip\":\"192.0.2.1\",\"pr\":7777,\"op\":[{\"k\":\"PI_COUNT\",\"v\":\"" +
        std::to_string(count) + "\"},{\"k\":\"BotPlayerCount\",\"v\":\"24\"},"
        "{\"k\":\"MaxPlayerCount\",\"v\":\"64\"}]}";
}
struct Segment {
    MemoryRegion region;
    std::vector<unsigned char> bytes;
};
struct Fixture {
    std::vector<Segment> segments;
    std::array<char, kJsonBytes> scratch{};
    std::uintptr_t failRead{};
    bool partialFailure{};
    bool registrationHeap{};
    bool forbiddenRead{};
    bool mutateAfterCopy{};
    bool mutated{};
    unsigned mutation{};
    unsigned payloadReads{};
    unsigned ipTerminatorReads{};
    std::size_t jsonSize{};

    Fixture() {
        Add(kHost, 0x1000, MEM_IMAGE, PAGE_READONLY, kHost);
        Add(kHost + 0x14A0000, 0x10000, MEM_IMAGE, PAGE_READWRITE, kHost);
        Add(kHost + 0x1798000, 0x1000, MEM_IMAGE, PAGE_READWRITE, kHost);
        Add(kJson, kJsonBytes + 0x1000, MEM_PRIVATE, PAGE_READWRITE, kJson);
        Add(kRegistrationHeap, 0x1000, MEM_PRIVATE, PAGE_READWRITE, kRegistrationHeap);
        Add(kIp, 0x1000, MEM_PRIVATE, PAGE_READWRITE, kIp);
        Add(kMemberData, 0x21000, MEM_PRIVATE, PAGE_READWRITE, kMemberData);
        IMAGE_DOS_HEADER dos{}; dos.e_magic = IMAGE_DOS_SIGNATURE; dos.e_lfanew = 0x80;
        Put(kHost, dos);
        IMAGE_NT_HEADERS64 nt{};
        nt.Signature = IMAGE_NT_SIGNATURE;
        nt.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt.FileHeader.NumberOfSections = 1;
        nt.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE;
        nt.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt.OptionalHeader.SizeOfImage = kImageSize;
        nt.OptionalHeader.SizeOfHeaders = 0x400;
        nt.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        Put(kHost + 0x80, nt);
        IMAGE_SECTION_HEADER data{};
        data.VirtualAddress = 0x14A0000; data.Misc.VirtualSize = 0x300000;
        data.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
        Put(kHost + 0x80 + sizeof(nt), data);
        Put(kService, std::uint32_t{3});
        Put(kRegistration + 0x10, std::uint64_t{8});
        Put(kRegistration + 0x18, std::uint64_t{15});
        const char opaque[] = "REG-TEST";
        Bytes(kRegistration, opaque, sizeof(opaque));
        Put(kMaximum, std::uint32_t{64});
        Put(kVector, kMemberData);
        Put(kVector + 8, kMemberData + 65 * 0x20);
        Put(kVector + 16, kMemberData + 128 * 0x20);
        Put(kIpHeader, kIp);
        Put(kIpHeader + 8, std::int32_t{10});
        Put(kIpHeader + 12, std::int32_t{16});
        // Contents before the terminator need not be materialized: production
        // admission is allowed to read ONLY the expected final UTF-16 NUL.
        Put(kIp + 18, std::uint16_t{0});
        SetJson(Json());
    }
    void Add(std::uintptr_t base, std::size_t size, DWORD type, DWORD protect, std::uintptr_t allocation) {
        segments.push_back({{base, allocation, size, MEM_COMMIT, type, protect},
            std::vector<unsigned char>(size)});
    }
    Segment* Find(std::uintptr_t address) noexcept {
        for (auto& segment : segments)
            if (address >= segment.region.base && address - segment.region.base < segment.bytes.size()) return &segment;
        return nullptr;
    }
    void Bytes(std::uintptr_t address, const void* value, std::size_t size) {
        auto* segment = Find(address);
        if (!segment || size > segment->bytes.size() - (address - segment->region.base)) {
            RS2_CHECK(false); return;
        }
        std::memcpy(segment->bytes.data() + address - segment->region.base, value, size);
    }
    template<class T> void Put(std::uintptr_t address, const T& value) { Bytes(address, &value, sizeof(value)); }
    void SetJson(const std::string& json) {
        jsonSize = json.size();
        Put(kGameMode, kJson);
        Put(kGameMode + 0x10, static_cast<std::uint64_t>(json.size()));
        Put(kGameMode + 0x18, static_cast<std::uint64_t>((std::max)(json.size(), std::size_t{4096})));
        Bytes(kJson, json.c_str(), json.size() + 1);
    }
    void HeapRegistration(std::uint64_t capacity = 4096) {
        registrationHeap = true;
        Put(kRegistration, kRegistrationHeap);
        Put(kRegistration + 0x18, capacity);
    }
    static bool Query(void* context, std::uintptr_t address, MemoryRegion* output, DWORD* error) noexcept {
        auto* segment = static_cast<Fixture*>(context)->Find(address);
        if (!segment) { *error = ERROR_NOACCESS; return false; }
        *output = segment->region; *error = ERROR_SUCCESS; return true;
    }
    static bool Read(void* context, std::uintptr_t address, void* output, std::size_t size, DWORD* error) noexcept {
        auto& f = *static_cast<Fixture*>(context);
        const bool registrationContent = (!f.registrationHeap && address >= kRegistration && address < kRegistration + 16) ||
            (address >= kRegistrationHeap && address < kRegistrationHeap + 0x1000);
        const bool memberContent = address >= kMemberData && address < kMemberData + 0x21000;
        const bool ipContent = address >= kIp && address < kIp + 0x1000;
        if (registrationContent || memberContent || (ipContent && (address != kIp + 18 || size != 2))) {
            f.forbiddenRead = true; *error = ERROR_ACCESS_DENIED; return false;
        }
        if (ipContent) ++f.ipTerminatorReads;
        auto* segment = f.Find(address);
        if (!segment || size > segment->bytes.size() - (address - segment->region.base)) {
            *error = ERROR_PARTIAL_COPY; return false;
        }
        if (address == f.failRead) {
            if (f.partialFailure) std::memcpy(output, segment->bytes.data() + address - segment->region.base,
                (std::min)(size, std::size_t{3}));
            *error = ERROR_PARTIAL_COPY; return false;
        }
        std::memcpy(output, segment->bytes.data() + address - segment->region.base, size);
        if (address == kJson && size == f.jsonSize) {
            ++f.payloadReads;
            if (f.mutateAfterCopy && !f.mutated) {
                f.mutated = true;
                switch (f.mutation) {
                case 0: f.Put(kMaximum, std::uint32_t{63}); break;
                case 1: f.Put(kService, std::uint32_t{0}); break;
                case 2: f.Put(kGameMode + 0x10, static_cast<std::uint64_t>(f.jsonSize + 1)); break;
                case 3: f.Put(kVector + 8, kMemberData + 66 * 0x20); break;
                case 4: f.HeapRegistration(); break;
                case 5: f.Put(kIpHeader + 12, std::int32_t{17}); break;
                }
            }
        }
        *error = ERROR_SUCCESS; return true;
    }
    PreparedReadContext Context() noexcept { return {{this, Query, Read}, kHost, kImageSize}; }
    Reason Run(const NativeCounts& expected = kCounts, PreparedSnapshot* output = nullptr) {
        scratch.fill('X');
        PreparedSnapshot local{};
        const auto reason = ReadPreparedState(Context(), expected, scratch.data(), scratch.size(), output ? output : &local);
        RS2_CHECK(std::all_of(scratch.begin(), scratch.end(), [](char c) { return c == 0; }));
        RS2_CHECK(!forbiddenRead);
        return reason;
    }
};

void ValidAndOpaqueReads() {
    Fixture f;
    PreparedSnapshot result{};
    RS2_CHECK(f.Run(kCounts, &result) == Reason::None);
    RS2_CHECK(EqualCounts(result.counts, kCounts) && result.membersCount == 65 && result.jsonBytes == f.jsonSize);
    RS2_CHECK(f.payloadReads == 1 && f.ipTerminatorReads == 2);
    f.HeapRegistration(1ULL << 32);
    f.Put(kGameMode + 0x18, std::uint64_t{1ULL << 32});
    RS2_CHECK(f.Run() == Reason::None); // Capacity is not the bounded used length.
    for (const bool allNull : {true, false}) {
        Fixture empty;
        empty.SetJson(Json(0));
        empty.Put(kVector, allNull ? std::uintptr_t{0} : kMemberData);
        empty.Put(kVector + 8, allNull ? std::uintptr_t{0} : kMemberData);
        empty.Put(kVector + 16, allNull ? std::uintptr_t{0} : kMemberData + 128 * 0x20);
        RS2_CHECK(empty.Run({0, 24, 64}) == Reason::None);
    }
    { Fixture inlineJson;
      inlineJson.Put(kGameMode + 0x10, std::uint64_t{2}); inlineJson.Put(kGameMode + 0x18, std::uint64_t{15});
      inlineJson.Bytes(kGameMode, "{}", 3);
      RS2_CHECK(inlineJson.Run() == Reason::PreparedMalformed); }
    { Fixture maximum;
      auto json = Json(); json.resize(kJsonBytes, ' '); maximum.SetJson(json);
      RS2_CHECK(maximum.Run() == Reason::None); }
}
void HeaderAndLengthRejections() {
    for (const auto state : {std::uint32_t{0}, std::uint32_t{1}, std::uint32_t{2}, std::uint32_t{4}, UINT32_MAX}) {
        Fixture f; f.Put(kService, state); RS2_CHECK(f.Run() == Reason::Unregistered && f.payloadReads == 0);
    }
    for (const auto header : {kRegistration, kGameMode}) {
        { Fixture f; f.Put(header + 0x10, std::uint64_t{0}); RS2_CHECK(f.Run() == Reason::PreparedUnavailable); }
        { Fixture f; f.Put(header + 0x18, std::uint64_t{0}); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
        { Fixture f; f.Put(header + 0x18, UINT64_MAX); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    }
    { Fixture f; f.HeapRegistration(); f.Put(kRegistration + 0x10, std::uint64_t{1025});
      RS2_CHECK(f.Run() == Reason::PreparedLimit); }
    { Fixture f; f.Put(kGameMode + 0x10, std::uint64_t{kJsonBytes + 1});
      f.Put(kGameMode + 0x18, std::uint64_t{kJsonBytes + 1}); RS2_CHECK(f.Run() == Reason::PreparedLimit); }
    { Fixture f; f.Put(kGameMode, std::uintptr_t{0}); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kGameMode, (std::numeric_limits<std::uintptr_t>::max)() - 8);
      RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kJson + f.jsonSize, std::uint8_t{'X'}); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kMaximum, std::uint32_t{63}); RS2_CHECK(f.Run() == Reason::PreparedMismatch); }
    for (const auto num : {std::int32_t{-1}, std::int32_t{0}, std::int32_t{1}, std::int32_t{17}}) {
        Fixture f; f.Put(kIpHeader + 8, num); RS2_CHECK(f.Run() == Reason::PublicIpUnavailable);
    }
    { Fixture f; f.Put(kIpHeader + 12, std::int32_t{1025}); RS2_CHECK(f.Run() == Reason::PublicIpUnavailable); }
    { Fixture f; f.Put(kIpHeader, std::uintptr_t{0}); RS2_CHECK(f.Run() == Reason::PublicIpUnavailable); }
    { Fixture f; f.Put(kIpHeader, kIp + 1); RS2_CHECK(f.Run() == Reason::PublicIpUnavailable); }
    { Fixture f; f.Put(kIp + 18, std::uint16_t{'X'}); RS2_CHECK(f.Run() == Reason::PublicIpUnavailable); }
}
void VectorAndJsonCoherence() {
    { Fixture f; f.Put(kVector + 8, kMemberData - 0x20); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kVector + 16, kMemberData + 0x20); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kVector + 8, kMemberData + 65 * 0x20 + 1); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kVector + 16, kMemberData + 128 * 0x20 + 1); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kVector, kMemberData + 1); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kVector + 16, kMemberData + 4097 * 0x20); RS2_CHECK(f.Run() == Reason::PreparedLimit); }
    { Fixture f; f.Put(kVector, std::uintptr_t{0}); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kVector, std::uintptr_t{0}); f.Put(kVector + 8, std::uintptr_t{0});
      f.Put(kVector + 16, std::uintptr_t{0}); RS2_CHECK(f.Run() == Reason::PreparedMismatch); }
    { Fixture f; f.Put(kVector + 8, kMemberData + 64 * 0x20); RS2_CHECK(f.Run() == Reason::PreparedMismatch); }
    { Fixture f; f.SetJson(Json(64)); RS2_CHECK(f.Run() == Reason::PreparedMismatch); }
    { Fixture f; auto duplicate = Json(); duplicate.insert(duplicate.size() - 2,
        ",{\"k\":\"PI_\\u0043OUNT\",\"v\":\"65\"}"); f.SetJson(duplicate);
      RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.SetJson(Json() + "trailing"); RS2_CHECK(f.Run() == Reason::PreparedMalformed); }
    { Fixture f; f.Put(kMaximum,std::uint32_t{63}); f.SetJson(Json() + "trailing");
      RS2_CHECK(f.Run() == Reason::PreparedMalformed); } // Stale numbers cannot hide unsupported syntax.
    { Fixture f; f.SetJson(Json(64)); f.mutateAfterCopy=true; f.mutation=0;
      RS2_CHECK(f.Run() == Reason::PreparedUnavailable); } // Nor a changing prepared lifetime.
    const Reason reasons[]{Reason::PreparedUnavailable, Reason::Unregistered, Reason::PreparedUnavailable,
        Reason::PreparedUnavailable, Reason::PreparedUnavailable, Reason::PreparedUnavailable};
    for (unsigned mutation = 0; mutation < 6; ++mutation) {
        Fixture f; f.mutateAfterCopy = true; f.mutation = mutation;
        PreparedSnapshot result{}; result.membersCount = 123;
        RS2_CHECK(f.Run(kCounts, &result) == reasons[mutation] && f.mutated && result.membersCount == 0);
    }
}
void FaultsAndScrubbing() {
    for (const auto address : {kService, kRegistration + 0x10, kGameMode + 0x18, kVector + 8,
        kMaximum, kJson}) {
        Fixture f; f.failRead = address; f.partialFailure = true;
        RS2_CHECK(f.Run() == Reason::PreparedUnavailable);
    }
    { Fixture f; f.failRead = kIp + 18; RS2_CHECK(f.Run() == Reason::PublicIpUnavailable); }
    { Fixture f; f.failRead = kJson + f.jsonSize; RS2_CHECK(f.Run() == Reason::PreparedUnavailable); }
    { Fixture f; f.Find(kJson)->region.size = 8; RS2_CHECK(f.Run() == Reason::PreparedUnavailable); }
    for (const auto protection : {DWORD{PAGE_NOACCESS}, DWORD{PAGE_READWRITE | PAGE_GUARD},
        DWORD{PAGE_READONLY}, DWORD{PAGE_EXECUTE_READWRITE}, DWORD{PAGE_WRITECOPY}}) {
        Fixture f; f.Find(kJson)->region.protect = protection; RS2_CHECK(f.Run() == Reason::PreparedUnavailable);
    }
    { Fixture f; f.Find(kJson)->region.type = MEM_MAPPED; RS2_CHECK(f.Run() == Reason::PreparedUnavailable); }
    { Fixture f; f.Find(kService)->region.allocationBase = kJson; RS2_CHECK(f.Run() == Reason::PreparedUnavailable); }
    { Fixture f; auto context = f.Context(); context.memory.read = nullptr;
      f.scratch.fill('X'); PreparedSnapshot result{};
      RS2_CHECK(ReadPreparedState(context, kCounts, f.scratch.data(), f.scratch.size(), &result) == Reason::PreparedUnavailable);
      RS2_CHECK(std::all_of(f.scratch.begin(), f.scratch.end(), [](char c) { return c == 0; })); }
    { Fixture f; std::array<char, 16> small{}; small.fill('X'); PreparedSnapshot result{};
      RS2_CHECK(ReadPreparedState(f.Context(), kCounts, small.data(), small.size(), &result) == Reason::PreparedLimit);
      RS2_CHECK(std::all_of(small.begin(), small.end(), [](char c) { return c == 0; })); }
    { Fixture f; f.scratch.fill('X');
      RS2_CHECK(ReadPreparedState(f.Context(), kCounts, f.scratch.data(), f.scratch.size(), nullptr) == Reason::PreparedUnavailable);
      RS2_CHECK(std::all_of(f.scratch.begin(), f.scratch.end(), [](char c) { return c == 0; })); }
    { Fixture f; PreparedSnapshot result{};
      RS2_CHECK(ReadPreparedState(f.Context(), kCounts, nullptr, kJsonBytes, &result) == Reason::PreparedUnavailable); }
}
} // namespace

void ReportingPreparedTests() {
    ValidAndOpaqueReads();
    HeaderAndLengthRejections();
    VectorAndJsonCoherence();
    FaultsAndScrubbing();
}

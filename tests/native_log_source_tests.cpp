#include "companion/steam_reporting_native_source.h"
#include "test_framework.h"
#include <array>
#include <cstring>

namespace rs2fix::testcases {
namespace {
using namespace reporting;
struct Image {
    static constexpr std::uintptr_t base = 0x180000000ULL;
    std::array<unsigned char, 0x10000> data{};
    NativeLogLayout layout{0x100, 0x1000, 0xA000, 0xA010, 0xA020, 0xA030, 0xA040, 0xA050,
        0xA060, 0x108, 0xA070, 0x110, 0x114, 0x118, 0x11C, 0x120, 0x128,
        0x130, 0x134, 0x138, 0x13C};
    std::size_t failAt = SIZE_MAX;
    bool readonlyArchive{};
    bool changeFallback{};
    unsigned logReads{};
    std::size_t maximumRead{};

    template<class T> void Put(std::size_t offset, T value) {
        std::memcpy(data.data() + offset, &value, sizeof(value));
    }
    void Pointer(std::size_t offset, std::uint32_t rva) { Put(offset, base + rva); }
    Image() {
        Pointer(layout.logSlot, layout.redirectorObject);
        Pointer(layout.redirectorObject, layout.redirectorVtable);
        Put<std::uint32_t>(0x1044, 7);
        Pointer(0x1034, 0x2000);
        Put<std::int32_t>(0x103C, 3);
        Put<std::int32_t>(0x1040, 20); // Native allocator slack is not an extra sink.
        Pointer(0x2000, 0x3000); Pointer(0x2008, 0x4000); Pointer(0x2010, 0x6000);
        Pointer(0x3000, layout.fileVtable); Pointer(0x3014, 0x7000);
        Put<std::uint32_t>(0x3010, 1); Put<std::uint32_t>(0x381C, 1);
        constexpr char16_t path[] = u"E:\\logs\\Launch.log";
        std::memcpy(data.data() + 0x301C, path, sizeof(path));
        Pointer(0x4000, layout.inheritedVtable);
        Put<std::uintptr_t>(0x4014, UINTPTR_MAX); Pointer(0x4020, 0x5000);
        Pointer(0x5000, layout.consoleVtable); Pointer(0x5100, layout.consoleVtable);
        Pointer(0x6000, layout.eventVtable);
        Pointer(0x7000, layout.archiveVtable); Put<std::uintptr_t>(0x7084, 0x980);
        Pointer(layout.managerSlot, 0x9000); Pointer(0x9000, layout.managerVtable);
        Put<std::uint32_t>(layout.forceFlush, 1); Put<std::uint32_t>(layout.logTimes, 1);
        Put<std::uint32_t>(layout.suppressionInitialized, 1);
        Pointer(layout.nameTable, 0xB000); Pointer(0xC7C0, 0xD000);
    }
    static bool Query(void* context, std::uintptr_t address, MemoryRegion* out, DWORD*) noexcept {
        auto& f = *static_cast<Image*>(context);
        if (address < base || address - base >= f.data.size()) return false;
        const auto offset = address - base;
        const std::size_t low = offset < 0x7000 ? 0 : (offset < 0x9000 ? 0x7000 : 0x9000);
        const std::size_t high = offset < 0x7000 ? 0x7000 : (offset < 0x9000 ? 0x9000 : f.data.size());
        *out = {base + low, base, high - low, MEM_COMMIT, MEM_IMAGE,
            static_cast<DWORD>(low == 0x7000 && f.readonlyArchive ? PAGE_READONLY : PAGE_READWRITE)};
        return true;
    }
    static bool Read(void* context, std::uintptr_t address, void* out, std::size_t size, DWORD*) noexcept {
        auto& f = *static_cast<Image*>(context);
        if (address < base || address - base >= f.data.size() || size > f.data.size() - (address - base)) return false;
        const auto offset = address - base;
        if (f.failAt >= offset && f.failAt - offset < size) return false;
        if (offset == f.layout.logSlot && ++f.logReads == 2 && f.changeFallback) f.Pointer(0x4020, 0x5100);
        if (size > f.maximumRead) f.maximumRead = size;
        std::memcpy(out, f.data.data() + offset, size);
        return true;
    }
    TransportReason Check(NativeLogSnapshot* result = nullptr, std::uint32_t thread = 7) {
        NativeLogSnapshot snapshot{};
        const NativeLogReadContext context{{this, Query, Read}, base, static_cast<std::uint32_t>(data.size()), thread, &layout};
        const auto reason = ReadNativeLogSnapshot(context, &snapshot);
        if (reason != TransportReason::None) {
            const NativeLogSnapshot zero{};
            RS2_CHECK(std::memcmp(&snapshot, &zero, sizeof(snapshot)) == 0);
        }
        if (result) *result = snapshot;
        return reason;
    }
};
} // namespace

void NativeLogSourceTests() {
    using T = TransportReason;
    Image good;
    NativeLogSnapshot snapshot{};
    RS2_CHECK(good.Check(&snapshot) == T::None);
    RS2_CHECK(snapshot.file == Image::base + 0x3000 && snapshot.archive == Image::base + 0x7000);
    RS2_CHECK(snapshot.sinkCount == 3 && snapshot.inheritedFallbacks[1] == Image::base + 0x5000);
    RS2_CHECK(snapshot.pathChars == 18 && snapshot.prefixMode == 1);
    RS2_CHECK(good.maximumRead <= 2048);
    RS2_CHECK(good.Check(nullptr, 8) == T::ProfileUnsafe);
    for (auto field : {good.layout.criticalError, good.layout.requestingExit,
            good.layout.fileReentry, good.layout.debugReentry, good.layout.inheritedReentry, good.layout.consoleReentry}) {
        Image f; f.Put<std::uint32_t>(field, 1); RS2_CHECK(f.Check() == T::AwaitingLogger);
    }
    { Image f; f.Put<std::uint32_t>(f.layout.forceFlush, 0); RS2_CHECK(f.Check() == T::ForceFlushMissing); }
    { Image f; f.Put<std::uint32_t>(f.layout.logTimes, 2); RS2_CHECK(f.Check() == T::FramingUnsupported); }
    { Image f; f.Put<std::uint64_t>(0xD000, 0x100000000000ULL); RS2_CHECK(f.Check() == T::CategorySuppressed); }
    { Image f; f.Put<std::uint32_t>(f.layout.suppressionInitialized, 0); f.failAt = 0xC7C0;
      RS2_CHECK(f.Check() == T::AwaitingLogger); } // Never inspect the name table before initialization.
    { Image f; f.Put<std::uint32_t>(0x1048, 1); RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.Put<std::int32_t>(0x103C, 9); RS2_CHECK(f.Check() == T::SinkUnsupported); }
    { Image f; f.Put<std::int32_t>(0x1040, 2); RS2_CHECK(f.Check() == T::SinkUnsupported); }
    { Image f; f.Pointer(0x2008, 0x3000); RS2_CHECK(f.Check() == T::SinkUnsupported); }
    { Image f; f.Pointer(0x6000, 0xA080); RS2_CHECK(f.Check() == T::SinkUnsupported); }
    { Image f; f.Pointer(0x5000, f.layout.fileVtable); RS2_CHECK(f.Check() == T::SinkUnsupported); }
    { Image f; f.Put<std::uintptr_t>(0x4014, 0x100); f.Put<std::uint32_t>(0x401C, 1);
      RS2_CHECK(f.Check() == T::SinkUnsupported); }
    { Image f; f.Pointer(0x9000, f.layout.fileVtable); RS2_CHECK(f.Check() == T::FileManagerUnsupported); }
    { Image f; f.Put<std::uint32_t>(0x381C, 0); RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.Put<std::uint32_t>(0x3820, 1); RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.Put<std::uint32_t>(0x300C, 1); RS2_CHECK(f.Check() == T::FramingUnsupported); }
    { Image f; f.Put<std::uint32_t>(0x3010, 0); RS2_CHECK(f.Check() == T::FramingUnsupported); }
    { Image f; f.readonlyArchive = true; RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.Put<std::uintptr_t>(0x7084,0); RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.Put<std::uintptr_t>(0x7084,UINTPTR_MAX); RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.Pointer(0x7000,f.layout.fileVtable); RS2_CHECK(f.Check() == T::ProfileUnsafe); }
    { Image f; f.Put<std::int32_t>(0x70AC, 4097); RS2_CHECK(f.Check() == T::ProfileUnsafe); }
    { Image f; f.Put<std::uint32_t>(0x7038, 1); RS2_CHECK(f.Check() == T::ReceiptUnavailable); }
    { Image f; f.Put<std::uint16_t>(0x301C, '\\'); RS2_CHECK(f.Check() == T::FramingUnsupported); }
    { Image f; f.failAt = 0x3100; RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.failAt = f.layout.forceFlush; RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.Put<std::uint32_t>(0x1044,0); RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.Put<std::uintptr_t>(0xC7C0,0); RS2_CHECK(f.Check() == T::AwaitingLogger); }
    { Image f; f.changeFallback = true; RS2_CHECK(f.Check() == T::AwaitingLogger); }
}
} // namespace rs2fix::testcases

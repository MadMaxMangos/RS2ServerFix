#include "leech_recovery_native_fixture.h"
#include "test_framework.h"
#include "pe_reader.h"
#include "companion/sha256.h"
#include <algorithm>
#include <array>
#include <chrono>
#include <climits>
#include <memory>

#if !defined(RS2_CURRENT_FULLDUMP_PATH)
#error Recovery name evidence requires the authenticated full-dump image path.
#endif

namespace rs2fix::testcases {
using namespace reporting;
namespace {
struct MetadataRandomFixture {
    unsigned calls{};
    bool fail{};
    static bool Fill(void* context,std::uint8_t* bytes,std::size_t count) noexcept {
        auto& self=*static_cast<MetadataRandomFixture*>(context);++self.calls;
        for(std::size_t i=0;i<count;++i) bytes[i]=static_cast<std::uint8_t>(i);
        return !self.fail;
    }
};
void MetadataMemberArguments() {
    auto storage=std::make_unique<RecoveryMetadataMembers>();
    auto& args=*storage;
    MetadataRandomFixture random{};
    const RecoveryRandomOps rng{&random,MetadataRandomFixture::Fill};
    RS2_CHECK(PrepareRecoveryMetadataMembers(args,2,rng));
    RS2_CHECK(random.calls==1 && args.count==2);
    RS2_CHECK(std::strcmp(args.text[0],"00010203-0405-4607-8809-0a0b0c0d0e0f")==0);
    RS2_CHECK(args.vector.end-args.vector.begin==2*sizeof(RecoveryBorrowedString));
    // Native PI above human capacity is preserved, never silently clamped.
    for (const auto count : {65u,66u}) {
        RS2_CHECK(PrepareRecoveryMetadataMembers(args,count,rng));
        RS2_CHECK(args.count==count && args.vector.end-args.vector.begin==count*sizeof(RecoveryBorrowedString));
    }
    RS2_CHECK(PrepareRecoveryMetadataMembers(args,kRecoveryMetadataMemberLimit,rng));
    for(std::uint32_t i=0;i<args.count;++i) {
        RS2_CHECK(args.strings[i].data==reinterpret_cast<std::uintptr_t>(args.text[i]));
        RS2_CHECK(args.strings[i].size==36 && args.strings[i].capacity==36 && args.strings[i].unused==0);
        RS2_CHECK(std::strlen(args.text[i])==36 && args.text[i][14]=='4');
        RS2_CHECK(args.text[i][19]=='8' || args.text[i][19]=='9' || args.text[i][19]=='a' || args.text[i][19]=='b');
    }
    const auto calls=random.calls;
    const unsigned char empty[sizeof(RecoveryMetadataMembers)]{};
    RS2_CHECK(!PrepareRecoveryMetadataMembers(args,kRecoveryMetadataMemberLimit+1,rng));
    RS2_CHECK(random.calls==calls && std::memcmp(&args,empty,sizeof(args))==0);
    random.fail=true;
    RS2_CHECK(!PrepareRecoveryMetadataMembers(args,2,rng));
    RS2_CHECK(std::memcmp(&args,empty,sizeof(args))==0);
    RS2_CHECK(!PrepareRecoveryMetadataMembers(args,1,{}));
    RS2_CHECK(std::memcmp(&args,empty,sizeof(args))==0);
    RS2_CHECK(PrepareRecoveryMetadataMembers(args,0,{}));
    RS2_CHECK(args.count==0 && args.vector.begin==args.vector.end && args.vector.end==args.vector.capacity);
}
void MetadataProfileAndCache() {
    auto fixture=std::make_unique<leech_fixture::NativeFixture>();auto& f=*fixture;f.LoadMetadataProfile();DWORD error{};
    RS2_CHECK(ValidateNativeRecoveryMetadataProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::Ready);
    // Informational cost check for the larger bounded overlay. Synthetic reads
    // and resolver calls exclude Windows/live-server costs; do not qualify a
    // game-thread latency budget from this measurement.
    double totalMicroseconds{},maximumMicroseconds{};
    constexpr unsigned timingSamples=32;
    for(unsigned i=0;i<timingSamples;++i) {
        const auto start=std::chrono::steady_clock::now();
        const auto result=ValidateNativeRecoveryMetadataProfile(f.base,f.host,f.Memory(),f.imports,&error);
        const auto elapsed=std::chrono::duration<double,std::micro>(std::chrono::steady_clock::now()-start).count();
        RS2_CHECK(result==ProfileResult::Ready);
        totalMicroseconds+=elapsed;maximumMicroseconds=(std::max)(maximumMicroseconds,elapsed);
    }
    std::cout<<"Metadata profile synthetic-memory cost: mean_us="<<totalMicroseconds/timingSamples
             <<" maximum_us="<<maximumMicroseconds<<"; not live game-thread qualification\n";
    const auto code=f.image[0xBA9490];f.image[0xBA9490]^=1;
    RS2_CHECK(ValidateNativeRecoveryMetadataProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::BytesMismatch);f.image[0xBA9490]=code;
    // Guard the actual omission regression: map insertion, a chained serializer
    // continuation, the indirect sink callback, and its executable jump table.
    for(const auto rva:{0xA46A70u,0xBFD537u,0xC11510u,0xC11174u}) {
        f.image[rva]^=1;
        RS2_CHECK(ValidateNativeRecoveryMetadataProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::BytesMismatch);
        f.image[rva]^=1;
    }
    f.Put<std::uintptr_t>(0x11CE348,f.base+0xA6CE90);
    RS2_CHECK(ValidateNativeRecoveryMetadataProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::PointerMismatch);
    f.Put<std::uintptr_t>(0x11CE348,f.base+0xA6F420);
    const auto& exception=leech_fixture::kMetadataPartitions[0].body.exceptions[0];f.image[exception.entryRva]^=1;
    RS2_CHECK(ValidateNativeRecoveryMetadataProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::UnwindMismatch);
    f.image[exception.entryRva]^=1;
    const auto& finalPart=leech_fixture::kMetadataPartitions[std::size(leech_fixture::kMetadataPartitions)-1];
    const auto& finalException=finalPart.body.exceptions[finalPart.body.exceptionCount-1];
    f.image[finalException.entryRva]^=1;
    RS2_CHECK(ValidateNativeRecoveryMetadataProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::UnwindMismatch);
    f.image[finalException.entryRva]^=1;
    const auto import=leech_fixture::NativeFixture::ImportAddress("MSVCP110.dll","?_Xlength_error@std@@YAXPEBD@Z");
    f.Put<std::uintptr_t>(0xE94968,import+1);
    RS2_CHECK(ValidateNativeRecoveryMetadataProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::ImportMismatch);
    f.Put<std::uintptr_t>(0xE94968,import);
    // Existing base qualification still holds with the supplemental modules.
    RS2_CHECK(ValidateNativeRecoveryProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::Ready);
    f.Put<std::uint32_t>(0x1798A00,66);f.Put<std::uint32_t>(0x17989F8,0);f.Put<std::uint32_t>(0x17989FC,64);
    RecoveryMetadataCache cache{};SetLastError(0x1234);
    RS2_CHECK(ReadRecoveryMetadataCache(f.Context(),&cache,&error)==RecoveryNativeResult::Ready && GetLastError()==0x1234);
    RS2_CHECK(cache.counts.pi==66 && cache.counts.bots==0 && cache.counts.maximum==64 && !cache.countdownBits && !cache.registrationChanged);
    f.Put<std::uint8_t>(0x14AAD88,2);
    RS2_CHECK(ReadRecoveryMetadataCache(f.Context(),&cache,&error)==RecoveryNativeResult::Shape && cache.counts.pi==0);
}
void ImageBackedComponentNames() {
    pe::Image image{};
    std::string error;
    const bool parsed = pe::ReadPeImage(RS2_CURRENT_FULLDUMP_PATH, &image, &error);
    RS2_CHECK(parsed);
    if (!parsed) return;
    Sha256Digest digest{};
    const bool hashed = HashBytesSha256(image.rawBytes.data(), image.rawBytes.size(), &digest);
    RS2_CHECK(hashed);
    if (!hashed) return;
    const bool qualified = std::strcmp(FormatSha256Upper(digest).data(),
        "0D8F3222AD796B024FB525118658BB1CE946E4357E35BA6E5ECD127883757393") == 0;
    RS2_CHECK(qualified);
    if (!qualified) return;

    // Independent file-backed custody, not a fixture copied from its own
    // constants: each new executable/exception input must match the pinned PE.
    std::vector<NativeLoggingProfile> profiles(std::begin(leech_fixture::kMetadataPartitions),std::end(leech_fixture::kMetadataPartitions));
    profiles.push_back(leech_fixture::kConsoleProduction);
    for(const auto& profile:profiles) {
        for(std::size_t i=0;i<profile.body.spanCount;++i) {
            const auto& span=profile.body.spans[i].span;std::vector<std::uint8_t> bytes;
            RS2_CHECK(pe::ReadImageRva(image,span.rva,span.size,&bytes,&error));
            RS2_CHECK(bytes.size()==span.size && !std::memcmp(bytes.data(),span.bytes,span.size));
        }
        for(std::size_t i=0;i<profile.body.pointerCount;++i) {
            const auto& pointer=profile.body.pointers[i];std::vector<std::uint8_t> bytes;
            RS2_CHECK(pe::ReadImageRva(image,pointer.slotRva,8,&bytes,&error));
            const std::uint64_t expected=image.imageBase+pointer.targetRva;
            RS2_CHECK(bytes.size()==sizeof(expected) && !std::memcmp(bytes.data(),&expected,sizeof(expected)));
        }
        for(std::size_t i=0;i<profile.body.exceptionCount;++i) {
            const auto& entry=profile.body.exceptions[i];std::vector<std::uint8_t> bytes;
            RS2_CHECK(pe::ReadImageRva(image,entry.entryRva,12,&bytes,&error));
            const std::uint32_t expected[]{entry.beginRva,entry.endRva,entry.unwindRva};
            RS2_CHECK(bytes.size()==sizeof(expected) && !std::memcmp(bytes.data(),expected,sizeof(expected)));
        }
    }

    // The stock registration calls use these name-pointer slots. Read their
    // targets from the preserved PE, then exercise the compiled reader against
    // those exact bytes; a fixture copied from the recipe cannot prove this.
    constexpr std::array<std::uint32_t, 8> namePointers{
        0x14AA9B0, 0x14AF1E8, 0x14AAD98, 0x14AACB0,
        0x14AF1E0, 0x14AF278, 0x14AF280, 0x14AF1D0
    };
    leech_fixture::NativeFixture fixture;
    for (std::size_t index = 0; index < namePointers.size(); ++index) {
        std::vector<std::uint8_t> pointerBytes;
        const bool pointerRead = pe::ReadImageRva(image, namePointers[index],
            sizeof(std::uint64_t), &pointerBytes, &error);
        RS2_CHECK(pointerRead);
        if (!pointerRead) return;
        std::uint64_t nameAddress{};
        std::memcpy(&nameAddress, pointerBytes.data(), sizeof(nameAddress));
        const bool insideImage = nameAddress >= image.imageBase &&
            nameAddress - image.imageBase <= UINT32_MAX;
        RS2_CHECK(insideImage);
        if (!insideImage) return;
        std::vector<std::uint8_t> nameBytes;
        const bool nameRead = pe::ReadImageRva(image,
            static_cast<std::uint32_t>(nameAddress - image.imageBase),
            64, &nameBytes, &error);
        RS2_CHECK(nameRead);
        if (!nameRead) return;
        const bool terminated = std::find(nameBytes.begin(), nameBytes.end(), 0) != nameBytes.end();
        RS2_CHECK(terminated);
        if (!terminated) return;
        fixture.Text(0x1490400 + static_cast<std::uint32_t>(index * 64),
            reinterpret_cast<const char*>(nameBytes.data()));
    }
    RecoveryNativeSnapshot snapshot{};
    RS2_CHECK(fixture.Snapshot(snapshot) == RecoveryNativeResult::Ready);
    fixture.Text(0x1490400, "AsyncDeferOperations");
    RS2_CHECK(fixture.Snapshot(snapshot) == RecoveryNativeResult::Readiness);
}
void CacheReaderContracts() {
    using R=RecoveryNativeResult;
    leech_fixture::NativeFixture f;
    auto snapshot=std::make_unique<RecoveryNativeSnapshot>();
    RS2_CHECK(f.Snapshot(*snapshot)==R::Ready);
    RS2_CHECK(snapshot->cacheSession.size==36 && snapshot->cacheSession.capacity==47);
    RS2_CHECK(snapshot->cacheSession.data!=snapshot->sdkSession.data &&
        !std::memcmp(snapshot->cacheBytes,snapshot->sdkBytes,36));

    f.Inline(f.layout.cacheSession);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Ready);
    RS2_CHECK(snapshot->cacheSession.size==0 && snapshot->cacheSession.capacity==15 && snapshot->cacheBytes[0]==0);
    RS2_CHECK(RequireNativeRecoveryReady(*snapshot)==R::Ready); // An empty cache is a valid recovery input.
    f.HeapString(f.layout.cacheSession,0x400,leech_fixture::NativeFixture::kInitialSession,47);
    f.ClearString(f.layout.cacheSession);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Ready);
    RS2_CHECK(snapshot->cacheSession.size==0 && snapshot->cacheSession.capacity==47 &&
        snapshot->cacheSession.data==f.heapBase+0x400 && snapshot->cacheBytes[0]==0);

    f.HeapString(f.layout.cacheSession,0x400,leech_fixture::NativeFixture::kInitialSession,47);
    f.Put<std::uint64_t>(f.layout.cacheSession+0x10,48);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Shape);
    f.Put<std::uint64_t>(f.layout.cacheSession+0x10,36);f.heap[0x400+36]='X';
    RS2_CHECK(f.Snapshot(*snapshot)==R::Shape);f.heap[0x400+36]=0;
    f.Put(f.layout.cacheSession,f.heapBase+0x100);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Alias); // Exact SDK backing storage is already owned.

    // Use an independent allocation so the identity budget, not an incidental
    // overlap with another fixture identity, rejects the oversized byte copy.
    f.HeapString(f.layout.cacheSession,0x1A0000,"bounded",1039);
    f.Put<std::uint64_t>(f.layout.cacheSession+0x10,1024);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Budget);
    f.HeapString(f.layout.cacheSession,0x400,leech_fixture::NativeFixture::kInitialSession,47);
    std::uint8_t header[32]{};std::memcpy(header,f.image.data()+f.layout.cacheSession,sizeof(header));
    f.changeSecondContentOffset=0x400;
    RS2_CHECK(f.Snapshot(*snapshot)==R::Changed);
    RS2_CHECK(!std::memcmp(header,f.image.data()+f.layout.cacheSession,sizeof(header)));
    const auto* bytes=reinterpret_cast<const std::uint8_t*>(snapshot.get());
    RS2_CHECK(std::all_of(bytes,bytes+sizeof(*snapshot),[](std::uint8_t byte){return byte==0;}));
}
void CoreIdentityContracts() {
    using R=RecoveryNativeResult;
    leech_fixture::NativeFixture f;
    auto before=std::make_unique<RecoveryNativeSnapshot>();
    auto fresh=std::make_unique<RecoveryNativeSnapshot>();
    RS2_CHECK(f.Snapshot(*before)==R::Ready && RequireNativeRecoveryReady(*before)==R::Ready);
    RS2_CHECK(before->authorizationToken.data!=before->coreGuid.data && before->coreGuid.size==36);
    // Complete only the original HB disposal. Its retained payload witnesses
    // stay intact while the separate token changes between owner snapshots.
    f.Put<std::int32_t>(f.hbObject+0x20+2*0x78,-1);std::memset(f.image.data()+f.layout.genericPool,0,0x78);
    f.heap[0x200]^=1;
    RS2_CHECK(f.Snapshot(*fresh)==R::Ready && RequireNativeRecoveryReady(*fresh)==R::Ready);
    RS2_CHECK(!std::memcmp(before->authorizationToken.header,fresh->authorizationToken.header,32));
    RS2_CHECK(std::memcmp(before->authorizationBytes,fresh->authorizationBytes,
        static_cast<std::size_t>(before->authorizationToken.size))!=0);
    RS2_CHECK(RequireHeartbeatFirstFree(*fresh,*before,(42u<<16)|2u)==R::Ready);
    f.HeapString(f.layout.authorizationToken,0x200,"short-new-token");
    RS2_CHECK(f.Snapshot(*fresh)==R::Ready && RequireNativeRecoveryReady(*fresh)==R::Ready);
    RS2_CHECK(fresh->authorizationToken.size!=before->authorizationToken.size);
    RS2_CHECK(RequireHeartbeatFirstFree(*fresh,*before,(42u<<16)|2u)==R::Ready);

    f.heap[0x500]='b'; // Valid non-nil GUID, different bytes under the identical header.
    RS2_CHECK(f.Snapshot(*fresh)==R::Ready && RequireNativeRecoveryReady(*fresh)==R::Ready);
    RS2_CHECK(!std::memcmp(before->coreGuid.header,fresh->coreGuid.header,32));
    RS2_CHECK(RequireHeartbeatFirstFree(*fresh,*before,(42u<<16)|2u)==R::Provenance);
}
void ReadinessIdentityRefusals() {
    using R=RecoveryNativeResult;
    leech_fixture::NativeFixture f;
    auto snapshot=std::make_unique<RecoveryNativeSnapshot>();
    const auto unreadiness=[&] {
        RS2_CHECK(f.Snapshot(*snapshot)==R::Ready);
        RS2_CHECK(RequireNativeRecoveryReady(*snapshot)==R::Readiness);
    };
    f.Inline(f.layout.coreGuid);unreadiness();
    f.HeapString(f.layout.coreGuid,0x500,"too-short",47);unreadiness();
    f.HeapString(f.layout.coreGuid,0x500,"00000000-0000-0000-0000-000000000000",47);unreadiness();
    f.HeapString(f.layout.coreGuid,0x500,leech_fixture::NativeFixture::kCoreGuid,47);
    std::memset(f.heap.data()+0x500,0,36);unreadiness();
    f.HeapString(f.layout.coreGuid,0x500,"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeeex",47);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Budget); // 37 data bytes cannot fit the 37-byte terminated witness.
    f.HeapString(f.layout.coreGuid,0x500,leech_fixture::NativeFixture::kCoreGuid,47);
    f.Put(f.layout.coreGuid,f.heapBase+0x100);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Alias);
    f.HeapString(f.layout.coreGuid,0x500,leech_fixture::NativeFixture::kCoreGuid,47);
    f.Inline(f.layout.authorizationToken);unreadiness();
    f.HeapString(f.layout.authorizationToken,0x200,leech_fixture::NativeFixture::kAuthorizationToken);
    f.Put<std::uint64_t>(f.layout.authorizationToken+0x10,64);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Shape);
    f.HeapString(f.layout.authorizationToken,0x200,leech_fixture::NativeFixture::kAuthorizationToken);
    f.Put(f.layout.auth,6u);unreadiness();f.Put(f.layout.auth,7u);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Ready && RequireNativeRecoveryReady(*snapshot)==R::Ready);
    f.changeSecondContentOffset=0x200;
    RS2_CHECK(f.Snapshot(*snapshot)==R::Changed); // Rotation inside one coherent read still refuses.
}
void RetainedFinishContracts() {
    using R=RecoveryNativeResult;
    leech_fixture::NativeFixture f;
    auto snapshot=std::make_unique<RecoveryNativeSnapshot>();
    const auto payload=f.finishObject+0x28;
    f.HeapString(payload,0x900,"retained-finish-session",47);
    RS2_CHECK(f.Snapshot(*snapshot)==R::Ready);
    RS2_CHECK(snapshot->finish.firstFree==0 && snapshot->finish.slots[0].references==-1 &&
        snapshot->strings[snapshot->finish.slots[0].firstString].size>0);
    RS2_CHECK(RequireFinishFirstFree(*snapshot)==R::Ready);
    snapshot->finish.firstFree=16;RS2_CHECK(RequireFinishFirstFree(*snapshot)==R::Pool);
    snapshot->finish.firstFree=0;snapshot->finish.slots[0].references=0;
    RS2_CHECK(RequireFinishFirstFree(*snapshot)==R::Provenance);
    snapshot->finish.slots[0].references=-1;snapshot->genericFree=1;
    RS2_CHECK(RequireFinishFirstFree(*snapshot)==R::Pool);
    f.Put<std::uint64_t>(payload+0x10,48);RS2_CHECK(f.Snapshot(*snapshot)==R::Shape);
    f.HeapString(payload,0x900,leech_fixture::NativeFixture::kInitialSession,47);
    f.Put(payload,f.heapBase+0x100);RS2_CHECK(f.Snapshot(*snapshot)==R::Alias);
    f.HeapString(payload,0x900,"retained-finish-session",47);
    f.Put<std::int32_t>(f.finishObject+0x20,-2);RS2_CHECK(f.Snapshot(*snapshot)==R::Pool);
}
}
void LeechRecoveryNativeTests(){
    using R=RecoveryNativeResult;
    MetadataMemberArguments();
    MetadataProfileAndCache();
    ImageBackedComponentNames();
    CacheReaderContracts();
    CoreIdentityContracts();
    ReadinessIdentityRefusals();
    RetainedFinishContracts();
    leech_fixture::NativeFixture f;DWORD error{};
    RS2_CHECK(ValidateNativeRecoveryProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::Ready);
    const auto code=f.image[0xBAB120];f.image[0xBAB120]^=1;
    RS2_CHECK(ValidateNativeRecoveryProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::BytesMismatch);f.image[0xBAB120]=code;
    f.Put<std::uintptr_t>(0x1277008,f.base+0xBF0E60);
    RS2_CHECK(ValidateNativeRecoveryProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::PointerMismatch);
    f.Put<std::uintptr_t>(0x1277008,f.base+0xBF0DB0);
    const auto recordByte=f.image[0x17E7120+4];f.image[0x17E7120+4]^=1;
    RS2_CHECK(ValidateNativeRecoveryProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::UnwindMismatch);
    f.image[0x17E7120+4]=recordByte;
    f.failImport=true;RS2_CHECK(ValidateNativeRecoveryProfile(f.base,f.host,f.Memory(),f.imports,&error)==ProfileResult::ImportMismatch);f.failImport=false;
    RecoveryNativeSnapshot before{},after{};SetLastError(0x1234);
    RS2_CHECK(f.Snapshot(before)==R::Ready);RS2_CHECK(GetLastError()==0x1234);
    RS2_CHECK(RequireNativeRecoveryReady(before)==R::Ready);RS2_CHECK(RequireFinishFirstFree(before)==R::Ready);
    RS2_CHECK(RequireCreateFirstFree(before)==R::Ready);RS2_CHECK(before.heartbeat.slots[0].vector.stringCount==64);
    RS2_CHECK(before.strings[before.heartbeat.slots[0].firstString].capacity==63);
    f.Put(f.layout.genericPool+0x78,1u);f.Put<std::int32_t>(f.finishObject+0x20,2);
    RS2_CHECK(f.Snapshot(after)==R::Pool); // Unknown partial native task forbids forward progress.
    RS2_CHECK(RequireRecoveryFinishInverse(f.Context(),f.base+f.finishObject,40,0,true,40u<<16,&error)==R::Ready);
    RS2_CHECK(RequireRecoveryFinishInverse(f.Context(),f.base+f.finishObject,40,0,true,(40u<<16)|1u,&error)==R::InvalidContext);
    f.Put<std::int32_t>(f.finishObject+0x20,0);
    RS2_CHECK(RequireRecoveryFinishInverse(f.Context(),f.base+f.finishObject,40,0,false,0,&error)==R::Ready);
    f.Put<std::int32_t>(f.finishObject+0x20,-1);f.Put(f.layout.genericPool+0x78,0u);
    f.Put<std::int32_t>(f.hbObject+0x20+2*0x78,-1);std::memset(f.image.data()+f.layout.genericPool,0,0x78);
    RS2_CHECK(f.Snapshot(after)==R::Ready);
    RS2_CHECK(RequireHeartbeatFirstFree(after,before,(42u<<16)|2u)==R::Ready); // Earlier populated firstfree is supported.
    // Native BAB380 clears initialized global Members values and END, retaining
    // allocation/capacity. Independent old HB VALUE payloads remain unchanged.
    std::memset(f.heap.data()+0x60000,0,64*32);
    for(unsigned i=0;i<64;++i)f.HeapPut<std::uint64_t>(0x60000+i*32+0x18,15);
    f.Put(f.layout.kernelVector+8,f.heapBase+0x60000);
    RS2_CHECK(f.Snapshot(after)==R::Ready);RS2_CHECK(after.kernelVector.stringCount==0 && before.kernelVector.stringCount==64);
    RS2_CHECK(RequireHeartbeatFirstFree(after,before,(42u<<16)|2u)==R::Ready);
    after.strings[after.heartbeat.slots[7].firstString].capacity++;
    RS2_CHECK(RequireHeartbeatFirstFree(after,before,(42u<<16)|2u)==R::Provenance);
    f.Put<std::uintptr_t>(f.layout.statusHook,f.base+0xBAB120);RS2_CHECK(f.Snapshot(after)==R::Hook);
    const RecoveryNativeSnapshot zero{};RS2_CHECK(!std::memcmp(&after,&zero,sizeof(after)));f.Put<std::uintptr_t>(f.layout.statusHook,0);
    f.Put(f.layout.jsonFree,f.base+0xD27804);RS2_CHECK(f.Snapshot(after)==R::Allocator);f.Put(f.layout.jsonFree,f.base+0xBFD630);
    f.Put(f.layout.core,2u);RS2_CHECK(f.Snapshot(after)==R::Ready);RS2_CHECK(RequireNativeRecoveryReady(after)==R::Readiness);f.Put(f.layout.core,1u);
    f.heap[0x200]=0;RS2_CHECK(f.Snapshot(after)==R::Ready);
    RS2_CHECK(RequireNativeRecoveryReady(after)==R::Readiness); // Stock BAB4A0 first-byte gate, independently of std::string size.
    f.heap[0x200]=before.authorizationBytes[0];
    f.Put<std::int32_t>(f.layout.publicIp+8,1);f.HeapPut<std::uint16_t>(0x300,0);
    RS2_CHECK(f.Snapshot(after)==R::Ready);RS2_CHECK(RequireNativeRecoveryReady(after)==R::Readiness);
    f.Put<std::int32_t>(f.layout.publicIp+8,before.publicIpCount);f.HeapPut<std::uint16_t>(0x300,before.publicIpChars[0]);
    f.Put<std::int32_t>(f.layout.publicIp+12,1);RS2_CHECK(f.Snapshot(after)==R::Shape);f.Put<std::int32_t>(f.layout.publicIp+12,32);
    f.Put(f.layout.publicIp,f.heapBase+0x100); // Public IP must not borrow the SDK string's allocation.
    RS2_CHECK(f.Snapshot(after)==R::Alias);f.Put(f.layout.publicIp,f.heapBase+0x300);
    f.Put<std::uint64_t>(f.hbObject+0x28+0x58,f.heapBase+0x10000+(kRecoveryVectorCapacity+1)*32);
    RS2_CHECK(f.Snapshot(after)==R::Budget);f.Put<std::uint64_t>(f.hbObject+0x28+0x58,f.heapBase+0x10000+128*32);
    f.changeSecond=true;RS2_CHECK(f.Snapshot(after)==R::Changed);f.changeSecond=false;
    f.Put<std::uint64_t>(f.hbObject+0x28+0x10,64);RS2_CHECK(f.Snapshot(after)==R::Shape);f.Put<std::uint64_t>(f.hbObject+0x28+0x10,before.strings[before.heartbeat.slots[0].firstString].size);
    f.Put(f.hbObject+0x28+0x78,f.heapBase+0x1000);RS2_CHECK(f.Snapshot(after)==R::Alias);
}
} // namespace rs2fix::testcases

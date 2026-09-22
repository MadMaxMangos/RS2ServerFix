// Build-time generator for our own EXE only. It never executes an input.
#include "pe_contract_lib.h"
#include "tool_paths.h"
#include "companion/sha256.h"
#include "shared/digest.h"
#include "../tests/steam_api_fixture.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <sstream>
#include <set>

namespace {
using Bytes = std::vector<std::uint8_t>;
std::string Array(const std::uint8_t* bytes, std::size_t size) {
    std::ostringstream out;
    out << '{';
    for (std::size_t i = 0; i < size; ++i) {
        if (i) out << ',';
        out << "0x" << std::hex << static_cast<unsigned>(bytes[i]);
    }
    out << '}';
    return out.str();
}
bool Emit(const wchar_t* path, const std::string& text) {
    // An explicit CMake-generated output, never an arbitrary game path.
    const std::filesystem::path output(path);
    std::wstring parent;
    std::string error;
    if (output.filename() != L"fixture_profile.h" ||
        !rs2fix::tooling::RequireAbsolutePlainDirectory(output.parent_path().c_str(), &parent, &error))
        return false;
    const DWORD attributes = GetFileAttributesW(path);
    if (attributes != INVALID_FILE_ATTRIBUTES &&
        (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY))) return false;
    HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;
    DWORD written{};
    const bool ok = text.size() <= MAXDWORD &&
        WriteFile(file, text.data(), static_cast<DWORD>(text.size()), &written, nullptr) &&
        written == text.size() && FlushFileBuffers(file);
    const bool closed = CloseHandle(file) != FALSE;
    return ok && closed;
}
bool ObserverProfile(const wchar_t* sdkPath, const rs2fix::pe::Image& image,
    const std::map<std::string, std::uint32_t>& symbols, const rs2fix::Sha256Digest& host,
    std::ostringstream& out, bool reporting=false) {
    constexpr const char* names[]{"FixtureSteamAccessor", "FixtureSteamAccessorReturn", "FixtureSteamAccessorEnd",
        "FixtureSteamLiteral", "FixtureSteamContext", "FixtureSteamPrivate", "FixtureSteamPublication",
        "FixtureSteamPublisherReturn", "FixtureSteamAdvertiseReturn"};
    for (const auto* name : names) if (!symbols.count(name)) return false;
    const auto accessor = symbols.at("FixtureSteamAccessor"), returned = symbols.at("FixtureSteamAccessorReturn");
    const auto end = symbols.at("FixtureSteamAccessorEnd");
    if (returned < accessor + 6 || end <= returned || end - accessor > 128) return false;
    Bytes code, literal, context;
    std::string error;
    if (!rs2fix::pe::ReadImageRva(image, accessor, end - accessor, &code, &error) ||
        !rs2fix::pe::ReadImageRva(image, symbols.at("FixtureSteamLiteral"), 19, &literal, &error) ||
        !rs2fix::pe::ReadImageRva(image, symbols.at("FixtureSteamContext"), 24, &context, &error) ||
        std::memcmp(literal.data(), "SteamGameServer013", 19)) return false;
    std::uint64_t callback{}, counter{}, object{};
    std::memcpy(&callback, context.data(), 8); std::memcpy(&counter, context.data() + 8, 8);
    std::memcpy(&object, context.data() + 16, 8);
    if (callback != image.imageBase + accessor || counter || object) return false;
    std::uint32_t factory{}, shutdown{}, init{};
    for (const auto& module : image.normalImports) {
        if (_stricmp(module.name.c_str(), "rs2_test_steam_api.dll")) continue;
        for (const auto& symbol : module.symbols) {
            if (symbol.byOrdinal) return false;
            if (symbol.name == "SteamInternal_FindOrCreateGameServerInterface") factory = symbol.iatRva;
            else if (symbol.name == "SteamInternal_GameServer_Init") init = symbol.iatRva;
            else if (symbol.name == "SteamGameServer_Shutdown") shutdown = symbol.iatRva;
            else if (reporting && symbol.name == "SteamGameServer_RunCallbacks") continue;
            else return false;
        }
    }
    if (!factory || !shutdown || !init || (factory & 7) || (shutdown & 7) || (init & 7) ||
        factory / 4096 != shutdown / 4096 || factory / 4096 != init / 4096) return false;
    const auto call = returned - accessor - 6;
    std::int32_t distance{}; std::memcpy(&distance, code.data() + call + 2, 4);
    if (code[call] != 0xFF || code[call + 1] != 0x15 || static_cast<std::int64_t>(returned) + distance != factory) return false;
    rs2fix::pe::Image sdk;
    std::wstring normalized;
    if (!rs2fix::tooling::RequireAbsolutePlainFile(sdkPath, &normalized, &error) ||
        !rs2fix::pe::ReadPeImage(normalized.c_str(), &sdk, &error) || sdk.machine != IMAGE_FILE_MACHINE_AMD64 ||
        !(sdk.characteristics & IMAGE_FILE_DLL) || !sdk.delayImports.empty()) return false;
    bool signature = false, factoryExport = false, initExport = false, shutdownExport = false;
    for (const auto& item : sdk.exports) {
        if (!item.forwarder.empty()) return false;
        if (item.name == "FixtureSteamSignature") {
            Bytes bytes;
            signature = rs2fix::pe::ReadImageRva(sdk, item.rva, sizeof(kFixtureSteamSignature), &bytes, &error) &&
                !std::memcmp(bytes.data(), kFixtureSteamSignature, sizeof(kFixtureSteamSignature));
        }
        if (item.name == "SteamInternal_FindOrCreateGameServerInterface") factoryExport = true;
        if (item.name == "SteamInternal_GameServer_Init") initExport = true;
        if (item.name == "SteamGameServer_Shutdown") shutdownExport = true;
    }
    rs2fix::Sha256Digest sdkHash{};
    if (!signature || !factoryExport || !initExport || !shutdownExport ||
        !rs2fix::HashBytesSha256(sdk.rawBytes.data(), sdk.rawBytes.size(), &sdkHash)) return false;
    out << "namespace observer {\ninline constexpr std::uint8_t kObserverFixtureAccessor[]" << Array(code.data(), code.size())
        << ";\ninline constexpr ByteSpan kObserverFixtureSpans[]{{" << accessor
        << ",sizeof(kObserverFixtureAccessor),kObserverFixtureAccessor}};\ninline constexpr Profile kFixtureObserverProfile{"
        << Array(host.data(), host.size()) << ',' << Array(sdkHash.data(), sdkHash.size()) << ','
        << sdk.sizeOfImage << ',' << sdk.coffTimestamp << "u," << sdk.checksum << ',' << factory << ',' << shutdown << ',' << init << ','
        << accessor << ',' << returned << ',' << symbols.at("FixtureSteamLiteral") << ',' << symbols.at("FixtureSteamContext") << ','
        << symbols.at("FixtureSteamPrivate") << ',' << symbols.at("FixtureSteamPublication") << ','
        << symbols.at("FixtureSteamPublisherReturn") << ',' << symbols.at("FixtureSteamAdvertiseReturn")
        << ",\"rs2_test_steam_api.dll\",kObserverFixtureSpans,1};\n}\n";
    return true;
}

bool ReportingFixtureModule(const wchar_t* path, const char* signatureName,
    const char* signatureText, std::size_t signatureBytes, const std::set<std::string>& exports,
    rs2fix::pe::Image* image, rs2fix::Sha256Digest* hash) {
    std::wstring normalized; std::string error;
    if (!rs2fix::tooling::RequireAbsolutePlainFile(path,&normalized,&error) ||
        !rs2fix::pe::ReadPeImage(normalized.c_str(),image,&error) ||
        image->machine!=IMAGE_FILE_MACHINE_AMD64 || image->optionalMagic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        !(image->characteristics&IMAGE_FILE_DLL) || image->tlsDirectoryRva || image->tlsDirectorySize ||
        !image->delayImports.empty() || image->normalImports.size()!=1 ||
        _stricmp(image->normalImports[0].name.c_str(),"kernel32.dll")) return false;
    std::set<std::string> names;
    bool signature=false;
    for (const auto& symbol:image->exports) {
        if (!symbol.forwarder.empty() || !names.insert(symbol.name).second) return false;
        if (symbol.name!=signatureName) continue;
        Bytes bytes;
        signature=rs2fix::pe::ReadImageRva(*image,symbol.rva,signatureBytes,&bytes,&error) &&
            !std::memcmp(bytes.data(),signatureText,signatureBytes);
    }
    return signature && names==exports && rs2fix::HashBytesSha256(image->rawBytes.data(),image->rawBytes.size(),hash);
}

bool ReportingProfile(const wchar_t* sdkPath, const wchar_t* clientPath,
    const rs2fix::pe::Image& image, const std::map<std::string,std::uint32_t>& symbols,
    const rs2fix::Sha256Digest& host, std::ostringstream& out) {
    // Only these own-code exported bodies/layouts are admitted. Production
    // selectors are generated separately from the immutable accepted inventory.
    constexpr const char* functions[]{"FixtureReportAdapter","FixtureReportDispatch",
        "FixtureReportTaskPump","FixtureReportUpdate","FixtureReportLeechTick",
        "FixtureReportSubsystem","FixtureReportWorldTick","FixtureReportEngine",
        "FixtureReportCallbackPump","FixtureReportBuilder","FixtureReportObjectNoop"};
    constexpr const char* data[]{"FixtureReportWorld","FixtureReportWorldInfoClass",
        "FixtureReportService","FixtureReportRegistration","FixtureReportGameMode",
        "FixtureReportMaximum","FixtureReportMembers","FixtureReportPublicIp","FixtureReportFullDirty",
        "FixtureReportTaskPool","FixtureReportSelectedId","FixtureReportInvalidId","FixtureReportCounter",
        "FixtureReportRegistry","FixtureReportMetadataVtable","FixtureReportObjectVtable",
        "FixtureReportSecondaryVtable","FixtureReportSecondaryTick"};
    constexpr const char* returns[]{"FixtureReportAdapterReturn","FixtureReportDispatchReturn",
        "FixtureReportTaskPumpReturn","FixtureReportUpdateReturn","FixtureReportTickReturn",
        "FixtureReportSubsystemReturn","FixtureReportWorldReturn","FixtureReportEngineReturn",
        "FixtureReportCallbackReturn"};
    for (const auto* name:data) if (!symbols.count(name)) { std::fprintf(stderr,"fixture-symbol-missing:%s\n",name); return false; }
    for (const auto* name:returns) if (!symbols.count(name)) return false;
    for (const auto* name:functions) if (!symbols.count(name) || !symbols.count(std::string(name)+"End")) return false;
    struct Span { std::uint32_t rva; Bytes bytes; bool code; };
    struct Exception { std::uint32_t rva,begin,end,unwind; };
    std::vector<Span> spans;
    std::vector<Exception> exceptions;
    std::vector<std::pair<std::uint32_t,std::uint32_t>> pointers;
    std::string error;
    const auto addSpan=[&](std::uint32_t rva,std::uint32_t size,bool code) {
        if (!size || size>8192 || spans.size()>=64) return false;
        for (const auto& prior:spans) {
            if (prior.rva==rva && prior.bytes.size()==size && prior.code==code) return true;
            if (rva<prior.rva+prior.bytes.size() && prior.rva<static_cast<std::uint64_t>(rva)+size) return false;
        }
        const auto* section=rs2fix::pe::FindSection(image,rva,size);
        if (!section || !(section->characteristics&IMAGE_SCN_MEM_READ) ||
            (section->characteristics&(IMAGE_SCN_MEM_WRITE|IMAGE_SCN_MEM_DISCARDABLE)) ||
            ((section->characteristics&IMAGE_SCN_MEM_EXECUTE)!=0)!=code) return false;
        Bytes bytes;
        if (!rs2fix::pe::ReadImageRva(image,rva,size,&bytes,&error)) return false;
        spans.push_back({rva,std::move(bytes),code}); return true;
    };
    const auto& directory=image.dataDirectories[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    Bytes pdata;
    if (!directory.virtualAddress || !directory.size || directory.size%12 ||
        !rs2fix::pe::ReadImageRva(image,directory.virtualAddress,directory.size,&pdata,&error)) return false;
    for (const auto* name:functions) {
        const auto begin=symbols.at(name),end=symbols.at(std::string(name)+"End");
        if (begin>=end || !addSpan(begin,end-begin,true)) return false;
        unsigned matched=0;
        for (std::size_t i=0;i<pdata.size();i+=12) {
            std::uint32_t entry[3]{}; std::memcpy(entry,pdata.data()+i,sizeof(entry));
            if (entry[0]!=begin) continue;
            if (++matched!=1 || entry[1]!=end || (entry[2]&3)) return false;
            Bytes unwind;
            if (!rs2fix::pe::ReadImageRva(image,entry[2],4,&unwind,&error) ||
                (unwind[0]&7)!=1 || (unwind[0]>>3)!=0) return false;
            const auto size=4+2*((static_cast<std::uint32_t>(unwind[2])+1)&~1U);
            if (!addSpan(entry[2],size,false)) return false;
            exceptions.push_back({directory.virtualAddress+static_cast<std::uint32_t>(i),begin,end,entry[2]});
        }
        // The inert UObject Noop is a leaf; all FRAME chain bodies have rows.
        if (!matched && std::string_view(name)!="FixtureReportObjectNoop") return false;
    }
    // C++ supplies the actual secondary vtable. Its tiny Tick override must
    // tail-transfer to our profiled subsystem; no guessed/skipped stack frame.
    const auto secondary=symbols.at("FixtureReportSecondaryTick");
    Bytes tail;
    if (!rs2fix::pe::ReadImageRva(image,secondary,5,&tail,&error) || tail[0]!=0xE9) return false;
    std::int32_t distance{}; std::memcpy(&distance,tail.data()+1,4);
    if (static_cast<std::int64_t>(secondary)+5+distance!=symbols.at("FixtureReportSubsystem") ||
        !addSpan(secondary,5,true)) return false;
    for (const auto* name:{"FixtureReportObjectVtable","FixtureReportMetadataVtable","FixtureReportSecondaryVtable"}) {
        const auto slot=symbols.at(name);
        const bool metadata=std::string_view(name)=="FixtureReportMetadataVtable";
        const auto count=metadata ? 4U : std::string_view(name)=="FixtureReportSecondaryVtable" ? 2U : 1U;
        constexpr std::uint32_t metadataOffsets[]{0,0x68,0x70,0xA0};
        for (unsigned i=0;i<count;++i) {
            const auto cell=slot+(metadata ? metadataOffsets[i] : i*8);
            Bytes bytes; std::uint64_t pointer{};
            if (!rs2fix::pe::ReadImageRva(image,cell,8,&bytes,&error)) return false;
            std::memcpy(&pointer,bytes.data(),8);
            if (pointer<image.imageBase || pointer-image.imageBase>=image.sizeOfImage) return false;
            const auto target=static_cast<std::uint32_t>(pointer-image.imageBase);
            const auto* section=rs2fix::pe::FindSection(image,target,1);
            if (!section || !(section->characteristics&IMAGE_SCN_MEM_EXECUTE)) return false;
            pointers.emplace_back(cell,target);
        }
    }
    std::uint32_t pump{},factory{};
    for (const auto& module:image.normalImports) if (!_stricmp(module.name.c_str(),"rs2_test_steam_api.dll"))
        for (const auto& symbol:module.symbols) {
            if (symbol.byOrdinal) return false;
            if (symbol.name=="SteamGameServer_RunCallbacks") pump=symbol.iatRva;
            if (symbol.name=="SteamInternal_FindOrCreateGameServerInterface") factory=symbol.iatRva;
        }
    if (!pump || !factory || pump/4096!=factory/4096 || (pump&7)) return false;
    rs2fix::pe::Image sdk,client;
    rs2fix::Sha256Digest sdkHash{},clientHash{};
    constexpr char clientSignature[]="RS2-OWN-INERT-STEAM-CLIENT-FIXTURE-NOT-FOR-DEPLOYMENT";
    if (!ReportingFixtureModule(sdkPath,"FixtureSteamSignature",kFixtureSteamSignature,sizeof(kFixtureSteamSignature),
            {"SteamInternal_FindOrCreateGameServerInterface","SteamInternal_GameServer_Init","SteamGameServer_Shutdown",
             "SteamGameServer_RunCallbacks","FixtureSteamReadSnapshot","FixtureSteamFactoryAlias","FixtureSteamSignature"},&sdk,&sdkHash) ||
        !ReportingFixtureModule(clientPath,"FixtureSteamClientSignature",clientSignature,sizeof(clientSignature),
            {"FixtureSteamClientSignature"},&client,&clientHash)) return false;
    out << "namespace reporting {\n";
    for (std::size_t i=0;i<spans.size();++i)
        out << "inline constexpr std::uint8_t kReportFixtureBytes" << i << "[]" << Array(spans[i].bytes.data(),spans[i].bytes.size()) << ";\n";
    out << "inline constexpr ReportingSpan kReportFixtureSpans[]{\n";
    for (std::size_t i=0;i<spans.size();++i)
        out << "{{" << spans[i].rva << ",sizeof(kReportFixtureBytes" << i << "),kReportFixtureBytes" << i << "},SpanKind::"
            << (spans[i].code ? "Code" : "ImmutableData") << "},\n";
    out << "};\ninline constexpr PointerRvaRecipe kReportFixturePointers[]{";
    for (const auto& pointer:pointers) out << '{' << pointer.first << ',' << pointer.second << "},";
    out << "};\ninline constexpr RuntimeFunctionRecipe kReportFixtureExceptions[]{";
    for (const auto& entry:exceptions) out << '{' << entry.rva << ',' << entry.begin << ',' << entry.end << ',' << entry.unwind << "},";
    out << "};\ninline constexpr ReportingProfile kFixtureReportingProfile{kReportFixtureSpans," << spans.size()
        << ",kReportFixturePointers," << pointers.size() << ",kReportFixtureExceptions," << exceptions.size()
        << ",{ " << pump << ",\"rs2_test_steam_api.dll\",\"SteamGameServer_RunCallbacks\"}};\n"
        << "inline constexpr ReportingIdentities kFixtureReportingIdentities{" << Array(host.data(),host.size()) << ','
        << Array(sdkHash.data(),sdkHash.size()) << ',' << Array(clientHash.data(),clientHash.size()) << ','
        << client.sizeOfImage << ',' << client.coffTimestamp << "u," << client.checksum << "};\n";
    out << "inline constexpr SourceLayout kFixtureSourceLayout{" << symbols.at("FixtureReportWorld") << ','
        << symbols.at("FixtureReportWorldInfoClass") << ',' << symbols.at("FixtureSteamPublication") << ',' << symbols.at("FixtureSteamPrivate") << "};\n";
    out << "inline constexpr PreparedLayout kFixturePreparedLayout{" << symbols.at("FixtureReportService") << ','
        << symbols.at("FixtureReportRegistration") << ',' << symbols.at("FixtureReportGameMode") << ','
        << symbols.at("FixtureReportMaximum") << ',' << symbols.at("FixtureReportMembers") << ','
        << symbols.at("FixtureReportPublicIp") << ',' << symbols.at("FixtureReportFullDirty") << "};\n";
    out << "inline constexpr TaskLayout kFixtureTaskLayout{" << symbols.at("FixtureReportTaskPool") << ','
        << symbols.at("FixtureReportSelectedId") << ',' << symbols.at("FixtureReportInvalidId") << ','
        << symbols.at("FixtureReportCounter") << ',' << symbols.at("FixtureReportRegistry") << ','
        << symbols.at("FixtureReportMetadataVtable") << ',' << symbols.at("FixtureReportBuilder") << ','
        << symbols.at("FixtureReportService") << "};\n";
    const auto pair=[&](const char* name) { return "{"+std::to_string(symbols.at(name))+","+std::to_string(symbols.at(name))+"}"; };
    out << "inline constexpr AncestryProfile kFixtureAncestryProfile{" << symbols.at(returns[0]) << ','
        << symbols.at(returns[1]) << ',' << symbols.at(returns[2]) << ',' << pair(returns[3]) << ',' << pair(returns[4]) << ','
        << symbols.at(returns[5]) << ',' << pair(returns[6]) << ',' << symbols.at(returns[7])
        << ",{1,2},3,{4,5}," << symbols.at(returns[8]) << "};\n}\n";
    return true;
}
}

int wmain(int argc, wchar_t** argv) {
    const bool reporting = argc == 7 && std::wcscmp(argv[3], L"--reporting-sdk") == 0 &&
        std::wcscmp(argv[5],L"--reporting-client")==0;
    const bool observer = reporting || (argc == 5 && std::wcscmp(argv[3], L"--observer-sdk") == 0);
    if (argc != 3 && !observer) return 2;
    rs2fix::tooling::ContractReport contract;
    if (!rs2fix::tooling::CheckArtifactContract(argv[1],
            reporting ? rs2fix::tooling::ArtifactKind::ReportingStartupFixture :
            observer ? rs2fix::tooling::ArtifactKind::ObserverStartupFixture :
                rs2fix::tooling::ArtifactKind::StartupFixture, &contract)) {
        for (const auto& finding : contract.findings) std::fprintf(stderr, "%s\n", finding.c_str());
        return 3;
    }
    const auto& image = contract.image;
    std::map<std::string, std::uint32_t> symbols;
    for (const auto& symbol : image.exports) {
        if (!symbol.forwarder.empty() || !symbols.emplace(symbol.name, symbol.rva).second) return 4;
    }
    constexpr const char* required[]{"FixtureState", "FixtureInitializerSlot",
        "FixtureInitializerThunk", "FixtureInitialize", "FixtureReturn", "FixtureInitializeEnd",
        "FixtureRecon", "FixtureReconLoad", "FixtureReconEnd", "FixtureBadConstant", "FixtureGoodConstant"};
    for (const auto* name : required) if (!symbols.count(name)) return 5;
    const auto fn = symbols.at("FixtureRecon"), end = symbols.at("FixtureReconEnd");
    const auto load = symbols.at("FixtureReconLoad"), constant = symbols.at("FixtureGoodConstant");
    const auto wrapper = symbols.at("FixtureInitialize"), returnRva = symbols.at("FixtureReturn");
    const auto wrapperEnd = symbols.at("FixtureInitializeEnd");
    if (end <= fn || end - fn > 1024 || load < fn || load + 12 > end || (load & 3) ||
        returnRva <= wrapper + 6 || wrapperEnd <= returnRva || wrapperEnd - wrapper > 1024) return 6;
    Bytes function, vector, slot, wrapperBytes, thunkBytes, entryBytes;
    std::string error;
    if (!rs2fix::pe::ReadImageRva(image, fn, end - fn, &function, &error) ||
        !rs2fix::pe::ReadImageRva(image, constant, 16, &vector, &error) ||
        !rs2fix::pe::ReadImageRva(image, symbols.at("FixtureInitializerSlot"), 8, &slot, &error) ||
        !rs2fix::pe::ReadImageRva(image, wrapper, wrapperEnd - wrapper, &wrapperBytes, &error) ||
        !rs2fix::pe::ReadImageRva(image, symbols.at("FixtureInitializerThunk"), 16, &thunkBytes, &error) ||
        !rs2fix::pe::ReadImageRva(image, image.entryPointRva, 16, &entryBytes, &error)) return 7;
    std::uint64_t pointer{};
    std::memcpy(&pointer, slot.data(), sizeof(pointer));
    if (pointer != image.imageBase + symbols.at("FixtureInitializerThunk")) return 8;
    const std::size_t offset = load - fn;
    constexpr std::uint8_t instruction[]{0xF3,0x0F,0x10,0x15};
    constexpr std::uint8_t nop[]{0x0F,0x1F,0x40,0x00};
    if (std::memcmp(function.data() + offset, instruction, 4) ||
        std::memcmp(function.data() + offset + 8, nop, 4)) return 9;
    std::int32_t oldDisplacement{};
    std::memcpy(&oldDisplacement, function.data() + offset + 4, 4);
    if (static_cast<std::int64_t>(load) + 8 + oldDisplacement != symbols.at("FixtureBadConstant")) return 10;
    const auto newDistance = static_cast<std::int64_t>(constant) - load - 8;
    if (newDistance < INT32_MIN || newDistance > INT32_MAX) return 11;
    const auto newDisplacement = static_cast<std::int32_t>(newDistance);
    for (std::size_t i = 0; i < 16; ++i)
        if (vector[i] != (i % 4 == 3 ? 0x38 : 0)) return 12;
    const auto callOffset = returnRva - wrapper - 6;
    if (wrapperBytes[callOffset] != 0xFF || wrapperBytes[callOffset + 1] != 0x15) return 13;
    std::int32_t iatDistance{};
    std::memcpy(&iatDistance, wrapperBytes.data() + callOffset + 2, 4);
    bool validIat{};
    for (const auto& module : image.normalImports)
        for (const auto& symbol : module.symbols)
            if (symbol.name == "X3DAudioInitialize" && !symbol.byOrdinal &&
                static_cast<std::int64_t>(returnRva) + iatDistance == symbol.iatRva) validIat = true;
    if (!validIat) return 14;
    rs2fix::Sha256Digest host{}, original{}, corrected{};
    if (!rs2fix::HashBytesSha256(image.rawBytes.data(), image.rawBytes.size(), &host) ||
        !rs2fix::HashBytesSha256(function.data(), function.size(), &original)) return 15;
    Bytes post = function;
    std::memcpy(post.data() + offset + 4, &newDisplacement, 4);
    if (!rs2fix::HashBytesSha256(post.data(), post.size(), &corrected)) return 16;
    std::ostringstream out;
    out << "#pragma once\n#include \"shared/startup_profile.h\"\n#include \"companion/recon_profile.h\"\n";
    if (observer) out << "#include \"companion/steam_observer_profile.h\"\n";
    if (reporting) out << "#include \"companion/steam_reporting_profile.h\"\n"
        "#include \"companion/steam_reporting_source.h\"\n#include \"companion/steam_reporting_prepared.h\"\n"
        "#include \"companion/steam_reporting_task.h\"\n#include \"companion/steam_reporting_ancestry.h\"\n";
    out << "namespace rs2fix {\ninline constexpr char kFixtureOnlySignature[] = \"RS2-OWN-CODE-FIXTURE-NOT-FOR-DEPLOYMENT\";\n";
    const Bytes spans[]{entryBytes, thunkBytes, wrapperBytes};
    const std::uint32_t rvas[]{image.entryPointRva, symbols.at("FixtureInitializerThunk"), wrapper};
    for (unsigned i = 0; i < 3; ++i)
        out << "inline constexpr std::uint8_t kFixtureSpan" << i << "[]" << Array(spans[i].data(), spans[i].size()) << ";\n";
    out << "inline constexpr ByteSpan kFixtureSpans[]{\n";
    for (unsigned i = 0; i < 3; ++i)
        out << '{' << rvas[i] << ",sizeof(kFixtureSpan" << i << "),kFixtureSpan" << i << "},\n";
    out << "};\ninline constexpr StartupProfile kFixtureStartupProfile{" << image.sizeOfImage << ',' << image.coffTimestamp
        << ",{ " << image.checksum << ",0},1," << image.entryPointRva << ',' << returnRva << ','
        << symbols.at("FixtureState") << ",1," << symbols.at("FixtureInitializerSlot") << ','
        << symbols.at("FixtureInitializerThunk") << ",kFixtureSpans,3};\n";
    out << "inline constexpr ReconProfile kFixtureReconProfile{" << fn << ',' << end - fn << ',' << load << ',' << load + 4
        << ',' << constant << ',' << static_cast<std::uint32_t>(oldDisplacement) << 'u' << ','
        << static_cast<std::uint32_t>(newDisplacement) << "u," << Array(function.data() + offset, 12) << ','
        << Array(vector.data(), vector.size()) << ',' << Array(host.data(), host.size()) << ','
        << Array(original.data(), original.size()) << ',' << Array(corrected.data(), corrected.size()) << "};\n";
    if (observer && !ObserverProfile(argv[4], image, symbols, host, out,reporting)) return 18;
    if (reporting && !ReportingProfile(argv[4],argv[6],image,symbols,host,out)) return 19;
    out << "}\n";
    if (!Emit(argv[2], out.str())) return 17;
    std::printf("fixture_host_sha256=%s function_size=%zu generated=true\n",
        rs2fix::FormatSha256Upper(host).data(), function.size());
    return 0;
}

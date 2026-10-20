#include "steam_reporting_native_log_fixture.h"
#include <Windows.h>
#include <cstring>
#include <cwchar>

#if !defined(RS2_REPORTING_FIXTURE)
#error This mock logger is for the owned startup host only.
#endif
extern "C" {
alignas(8) unsigned char FixtureNativeLogState[rs2fix::fixture_log::kBytes]{};
alignas(8) unsigned char FixtureNativeLogBuffer[8192+7]{};
volatile DWORD FixtureNativeLogErrors{};
extern const std::uintptr_t FixtureNativeRedirectorVtable[],FixtureNativeFileVtable[],FixtureNativeArchiveVtable[],FixtureNativeManagerVtable[];
// One nonvariadic Windows64 call, the same shape used by the adapter. The
// generated OWN profile authenticates this body's bytes/pdata and static imports.
__declspec(noinline) void FixtureNativeLog(void* receiver,const wchar_t* message) {
    using namespace rs2fix::fixture_log;
    if(receiver!=FixtureNativeLogState+kRedirector || !message) {++FixtureNativeLogErrors;return;}
    std::size_t count{};
    while(count<8192 && message[count]) {
        if(message[count]<32 || message[count]>126){++FixtureNativeLogErrors;return;}
        FixtureNativeLogBuffer[5+count]=static_cast<unsigned char>(message[count]);++count;
    }
    if(message[count]){++FixtureNativeLogErrors;return;}
    FixtureNativeLogBuffer[0]='L';FixtureNativeLogBuffer[1]='o';FixtureNativeLogBuffer[2]='g';
    FixtureNativeLogBuffer[3]=':';FixtureNativeLogBuffer[4]=' ';
    FixtureNativeLogBuffer[5+count]='\r';FixtureNativeLogBuffer[6+count]='\n';
    HANDLE file{};std::memcpy(&file,FixtureNativeLogState+kArchive+0x84,sizeof(file));
    DWORD written{};
    // Current game File::Serialize's FORCELOGFLUSH path calls archive+0x98,
    // pinned to RVA 0xFDA0: it drains buffered bytes with WriteFile, not a disk
    // FlushFileBuffers call. Receipts require visibility, not power-loss durability.
    if(!WriteFile(file,FixtureNativeLogBuffer,static_cast<DWORD>(count+7),&written,nullptr) ||
        written!=count+7) ++FixtureNativeLogErrors;
}
}
namespace {
template<class T> void Put(std::uint32_t offset,const T& value) noexcept {
    std::memcpy(FixtureNativeLogState+offset,&value,sizeof(value));
}
std::uintptr_t Address(std::uint32_t offset) noexcept {
    return reinterpret_cast<std::uintptr_t>(FixtureNativeLogState+offset);
}
HANDLE g_file=INVALID_HANDLE_VALUE;
}
bool PrepareFixtureNativeLog() noexcept {
    using namespace rs2fix::fixture_log;
    auto* path=reinterpret_cast<wchar_t*>(FixtureNativeLogState+kFile+0x1C);
    const auto length=GetModuleFileNameW(nullptr,path,1024);
    if(!length || length>=1024) return false;
    auto* last=std::wcsrchr(path,L'\\');
    if(!last || static_cast<std::size_t>(last-path)+12>=1024) return false;
    std::wmemcpy(last+1,L"Launch.log",11);
    Put(kSlot,Address(kRedirector));
    Put(kRedirector,reinterpret_cast<std::uintptr_t>(FixtureNativeRedirectorVtable));
    Put(kRedirector+0x34,Address(kSinks));Put(kRedirector+0x3C,std::int32_t{1});
    Put(kRedirector+0x40,std::int32_t{1});Put(kRedirector+0x44,GetCurrentThreadId());
    Put(kSinks,Address(kFile));Put(kFile,reinterpret_cast<std::uintptr_t>(FixtureNativeFileVtable));
    Put(kFile+0x10,std::uint32_t{1});Put(kFile+0x14,Address(kArchive));
    Put(kArchive,reinterpret_cast<std::uintptr_t>(FixtureNativeArchiveVtable));
    Put(kManagerSlot,Address(kManager));Put(kManager,reinterpret_cast<std::uintptr_t>(FixtureNativeManagerVtable));
    Put(kForce,std::uint32_t{1});Put(kInitialized,std::uint32_t{1});
    Put(kNameSlot,Address(kNames));Put(kNames+0x17C0,Address(kLogName));
    g_file=CreateFileW(path,GENERIC_WRITE,FILE_SHARE_READ,nullptr,CREATE_NEW,
        FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
    Put(kArchive+0x84,g_file);
    Put(kFile+0x81C,std::uint32_t{g_file!=INVALID_HANDLE_VALUE ? 1U : 0U});
    // An existing owned obstruction is a deliberate WaitingLogger scenario,
    // not an excuse to bypass profile checks or fail the original host workflow.
    return true;
}
void CloseFixtureNativeLog() noexcept {
    using namespace rs2fix::fixture_log;
    Put(kExit,std::uint32_t{1});
    if(g_file!=INVALID_HANDLE_VALUE){CloseHandle(g_file);g_file=INVALID_HANDLE_VALUE;}
}

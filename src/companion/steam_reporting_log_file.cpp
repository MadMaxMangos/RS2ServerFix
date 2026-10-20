#include "companion/steam_reporting_log_file.h"
#include <cwchar>
#include <cstring>
#include <iterator>

namespace rs2fix::reporting {
namespace {
TransportReason Error(NativeLogFile& file,TransportReason reason,DWORD error) noexcept {
    file.lastError=error ? error : ERROR_GEN_FAILURE; return reason;
}
bool Device(const std::uint16_t* component,std::size_t chars) noexcept {
    std::size_t stem{};
    while (stem<chars && component[stem]!='.') ++stem;
    while (stem && component[stem-1]==' ') --stem;
    if (!stem || stem>7) return false;
    wchar_t name[8]{};
    for (std::size_t i=0;i<stem;++i) {
        const auto ch=component[i];
        name[i]=static_cast<wchar_t>(ch>='a' && ch<='z' ? ch-('a'-'A') : ch);
    }
    if (!wcscmp(name,L"CON") || !wcscmp(name,L"PRN") || !wcscmp(name,L"AUX") ||
        !wcscmp(name,L"NUL") || !wcscmp(name,L"CONIN$") || !wcscmp(name,L"CONOUT$")) return true;
    return stem==4 && (!wcsncmp(name,L"COM",3) || !wcsncmp(name,L"LPT",3)) &&
        ((name[3]>=L'1' && name[3]<=L'9') || name[3]==0xB9 || name[3]==0xB2 || name[3]==0xB3);
}
bool Plain(HANDLE handle,bool directory,DWORD& error) noexcept {
    BY_HANDLE_FILE_INFORMATION info{};
    if (GetFileType(handle)!=FILE_TYPE_DISK || !GetFileInformationByHandle(handle,&info)) {
        error=GetLastError(); if (!error) error=ERROR_INVALID_HANDLE; return false;
    }
    if ((info.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT) ||
        static_cast<bool>(info.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)!=directory) {
        error=ERROR_REPARSE_TAG_INVALID; return false;
    }
    return true;
}
struct Ancestors {
    // At most 510 nonempty one-character components fit in a 1023-char path.
    HANDLE held[512]{};
    std::size_t count{};
    ~Ancestors() { while (count) CloseHandle(held[--count]); }
    bool Hold(const wchar_t* path,DWORD& error) noexcept {
        if (count==std::size(held)) { error=ERROR_TOO_MANY_OPEN_FILES; return false; }
        const auto handle=CreateFileW(path,FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,
            nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr);
        if (handle==INVALID_HANDLE_VALUE) { error=GetLastError(); return false; }
        if (!Plain(handle,true,error)) { CloseHandle(handle); return false; }
        held[count++]=handle; return true;
    }
};
bool FinalName(HANDLE handle,const wchar_t* path,DWORD& error) noexcept {
    wchar_t finalName[kNativeLogPathChars+4]{};
    const DWORD length=GetFinalPathNameByHandleW(handle,finalName,static_cast<DWORD>(std::size(finalName)),
        FILE_NAME_NORMALIZED|VOLUME_NAME_DOS);
    if (!length) { error=GetLastError(); return false; }
    if (length>=std::size(finalName) || wcsncmp(finalName,L"\\\\?\\",4) ||
        CompareStringOrdinal(finalName+4,-1,path,-1,TRUE)!=CSTR_EQUAL) {
        error=ERROR_BAD_PATHNAME; return false;
    }
    return true;
}
}
bool NativeLogPathSyntax(const std::uint16_t* input,std::size_t chars,
    wchar_t (&path)[kNativeLogPathChars]) noexcept {
    path[0]=0;
    if (!input || chars<4 || chars>=kNativeLogPathChars ||
        !((input[0]>='A' && input[0]<='Z') || (input[0]>='a' && input[0]<='z')) ||
        input[1]!=':' || input[2]!='\\') return false;
    for (std::size_t i=3,begin=3;i<=chars;++i) {
        const auto ch=i<chars ? input[i] : 0;
        if (i<chars && ch!='\\') {
            if (ch<0x20 || ch=='/' || ch==':' || ch=='?' || ch=='*' ||
                ch=='"' || ch=='<' || ch=='>' || ch=='|') return false;
            continue;
        }
        if (i==begin || input[i-1]=='.' || input[i-1]==' ' ||
            Device(input+begin,i-begin)) return false;
        begin=i+1;
    }
    for (std::size_t i=0;i<chars;++i) path[i]=static_cast<wchar_t>(input[i]);
    path[chars]=0;
    return true;
}
TransportReason OpenNativeLogFile(NativeLogFile& file,const std::uint16_t* input,
    std::size_t chars) noexcept {
    if (file.identity.valid || (file.handle && file.handle!=INVALID_HANDLE_VALUE))
        return Error(file,TransportReason::ReceiptUnavailable,ERROR_ALREADY_INITIALIZED);
    wchar_t path[kNativeLogPathChars]{};
    if (!NativeLogPathSyntax(input,chars,path))
        return Error(file,TransportReason::FramingUnsupported,ERROR_BAD_PATHNAME);
    wchar_t full[kNativeLogPathChars]{};
    const auto normalized=GetFullPathNameW(path,static_cast<DWORD>(std::size(full)),full,nullptr);
    if (!normalized || normalized>=std::size(full) ||
        CompareStringOrdinal(path,-1,full,-1,TRUE)!=CSTR_EQUAL)
        return Error(file,TransportReason::FramingUnsupported,ERROR_BAD_PATHNAME);
    wchar_t root[4]{path[0],L':',L'\\',0};
    if (GetDriveTypeW(root)!=DRIVE_FIXED)
        return Error(file,TransportReason::FramingUnsupported,ERROR_NOT_SUPPORTED);
    DWORD error{};
    Ancestors ancestors;
    if (!ancestors.Hold(root,error)) return Error(file,TransportReason::ReceiptUnavailable,error);
    for (std::size_t i=3;i<chars;++i) {
        if (path[i]!=L'\\') continue;
        path[i]=0;
        const bool held=ancestors.Hold(path,error);
        path[i]=L'\\';
        if (!held) return Error(file,TransportReason::ReceiptUnavailable,error);
    }
    // Pin ancestors only while validating/opening. Releasing these temporary
    // directory handles does not obstruct native close/next-start rotation.
    const auto handle=CreateFileW(path,GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_SEQUENTIAL_SCAN,nullptr);
    if (handle==INVALID_HANDLE_VALUE) return Error(file,TransportReason::ReceiptUnavailable,GetLastError());
    NativeLogFile candidate{};
    candidate.handle=handle;
    LARGE_INTEGER size{};
    bool ok=Plain(handle,false,error) && FinalName(handle,path,error) &&
        QueryFileIdentity128(handle,&candidate.identity,&error);
    if (ok && (!GetFileSizeEx(handle,&size) || size.QuadPart<0)) {
        error=GetLastError(); if (!error) error=ERROR_INVALID_DATA; ok=false;
    }
    if (ok) {
        candidate.initialEOF=static_cast<std::uint64_t>(size.QuadPart);
        candidate.maximumSize=candidate.initialEOF;
        candidate.initialAtLineBoundary=!candidate.initialEOF;
        if (candidate.initialEOF) {
            LARGE_INTEGER at{}; at.QuadPart=size.QuadPart-1;
            char tail{}; DWORD got{};
            if (!SetFilePointerEx(handle,at,nullptr,FILE_BEGIN) ||
                !ReadFile(handle,&tail,1,&got,nullptr) || got!=1) {
                error=GetLastError(); if (!error) error=ERROR_READ_FAULT; ok=false;
            } else candidate.initialAtLineBoundary=tail=='\n';
        }
    }
    if (!ok) { CloseHandle(handle); return Error(file,TransportReason::ReceiptUnavailable,error); }
    std::wmemcpy(candidate.path,path,chars+1);
    file=candidate;
    return TransportReason::None;
}
TransportReason CheckNativeLogFile(NativeLogFile& file,std::uint64_t* size) noexcept {
    if (size) *size=0;
    if (!size || !file.handle || file.handle==INVALID_HANDLE_VALUE || !file.identity.valid)
        return Error(file,TransportReason::ReceiptUnavailable,ERROR_INVALID_HANDLE);
    FileIdentity128 current{}; DWORD error{};
    if (!QueryFileIdentity128(file.handle,&current,&error))
        return Error(file,TransportReason::ReceiptUnavailable,error);
    if (!SameFileIdentity128(file.identity,current))
        return Error(file,TransportReason::FileIdentityChanged,ERROR_INVALID_DATA);
    LARGE_INTEGER length{};
    if (!GetFileSizeEx(file.handle,&length) || length.QuadPart<0)
        return Error(file,TransportReason::ReceiptUnavailable,GetLastError());
    const auto now=static_cast<std::uint64_t>(length.QuadPart);
    if (now<file.maximumSize)
        return Error(file,TransportReason::FileTruncated,ERROR_INVALID_DATA);
    file.maximumSize=now; *size=now; file.lastError=ERROR_SUCCESS;
    return TransportReason::None;
}
TransportReason ReadNativeLogFile(NativeLogFile& file,std::uint64_t offset,
    void* output,DWORD requested,DWORD* received) noexcept {
    if (received) *received=0;
    if (!received || (!output && requested) || requested>kNativeReadCycleBytes || offset>INT64_MAX)
        return Error(file,TransportReason::ReceiptUnavailable,ERROR_INVALID_PARAMETER);
    std::uint64_t size{};
    auto result=CheckNativeLogFile(file,&size);
    if (result!=TransportReason::None) return result;
    if (offset>size) return Error(file,TransportReason::FileTruncated,ERROR_HANDLE_EOF);
    if (!requested || offset==size) return TransportReason::None;
    LARGE_INTEGER at{}; at.QuadPart=static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file.handle,at,nullptr,FILE_BEGIN) ||
        !ReadFile(file.handle,output,requested,received,nullptr))
        return Error(file,TransportReason::ReceiptUnavailable,GetLastError());
    if (*received>requested)
        return Error(file,TransportReason::ReceiptUnavailable,ERROR_INVALID_DATA);
    // Detect truncation observed during this read, before consuming its bytes.
    result=CheckNativeLogFile(file,&size);
    if (result!=TransportReason::None) *received=0;
    return result;
}
TransportReason RequalifyNativeLogFile(NativeLogFile& file,const std::uint16_t* path,
    std::size_t chars) noexcept {
    wchar_t proposed[kNativeLogPathChars]{};
    if (!file.identity.valid || !NativeLogPathSyntax(path,chars,proposed) ||
        CompareStringOrdinal(file.path,-1,proposed,-1,TRUE)!=CSTR_EQUAL)
        return Error(file,TransportReason::FramingUnsupported,ERROR_BAD_PATHNAME);
    NativeLogFile candidate{};
    auto reason=OpenNativeLogFile(candidate,path,chars);
    if (reason!=TransportReason::None) { file.lastError=candidate.lastError; return reason; }
    const bool same=SameFileIdentity128(file.identity,candidate.identity);
    CloseNativeLogFile(candidate);
    if (!same) return Error(file,TransportReason::FileIdentityChanged,ERROR_INVALID_DATA);
    std::uint64_t size{};
    return CheckNativeLogFile(file,&size);
}
void CloseNativeLogFile(NativeLogFile& file) noexcept {
    if (file.handle && file.handle!=INVALID_HANDLE_VALUE) CloseHandle(file.handle);
    file.handle=nullptr;
    // Keep immutable identity/initialEOF for terminal evidence; never reset a
    // receipt cursor or silently turn a different file into the same generation.
}
}

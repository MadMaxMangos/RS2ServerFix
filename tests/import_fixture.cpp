#include <Windows.h>
extern "C" __declspec(dllimport) void WINAPI X3DAudioInitialize(UINT32, FLOAT, BYTE*);
int main(int argc, char**) {
    if (argc > 1) { BYTE handle[20]{}; X3DAudioInitialize(3, 343.5f, handle); }
    return 0;
}

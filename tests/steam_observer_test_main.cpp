#include "test_framework.h"
namespace rs2fix::testcases {
void RunObserverDispatchTests();
void RunObserverTransactionTests();
void RunObserverProfileTests();
}
void RunSteamObserverLogTests();
int main() {
    rs2fix::testcases::RunObserverDispatchTests();
    RunSteamObserverLogTests();
    rs2fix::testcases::RunObserverTransactionTests();
    rs2fix::testcases::RunObserverProfileTests();
    std::cout << "checks=" << rs2fix::test::g_checks << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures ? 1 : 0;
}

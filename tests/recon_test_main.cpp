#include "test_framework.h"
namespace rs2fix::testcases { void RunReconTests(); }
int main() {
    rs2fix::testcases::RunReconTests();
    std::cout << "checks=" << rs2fix::test::g_checks << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures ? 1 : 0;
}

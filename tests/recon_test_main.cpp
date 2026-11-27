#include "test_framework.h"
namespace rs2fix::testcases { void RunReconTests(); void RunPackageCheckTests(); }
int main() {
    rs2fix::testcases::RunReconTests();
    rs2fix::testcases::RunPackageCheckTests();
    std::cout << "checks=" << rs2fix::test::g_checks << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures ? 1 : 0;
}

#include "test_framework.h"
namespace rs2fix::testcases { void RunProfileEvidenceTests(); }
int main() {
    rs2fix::testcases::RunProfileEvidenceTests();
    std::cout << "checks=" << rs2fix::test::g_checks << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures ? 1 : 0;
}

#include "test_framework.h"

namespace rs2fix::testcases {
void RunResolverTests();
void RunLoaderTests();
void RunPathTests();
void RunCompanionTests();
void RunHostHashTests();
void RunPeReaderTests();
void RunManifestTests();
void RunRuntimeInventoryTests();
void RunStartupContextTests();
}
int main() {
    using namespace rs2fix::testcases;
    RunResolverTests();
    RunLoaderTests();
    RunPathTests();
    RunCompanionTests();
    RunHostHashTests();
    RunPeReaderTests();
    RunManifestTests();
    RunRuntimeInventoryTests();
    RunStartupContextTests();
    std::cout << "checks=" << rs2fix::test::g_checks << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures == 0 ? 0 : 1;
}

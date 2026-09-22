#include "test_framework.h"
void ReportingConfigTests();
void ReportingStateTests();
void ReportingJsonTests();
void ReportingSourceTests();
void ReportingStatusTests();
void ReportingPreparedTests();
void ReportingCaptureTests();
void ReportingTaskTests();
void ReportingClientTests();
void ReportingForwardTests();
namespace rs2fix::testcases { void ReportingProfileTests(); void ReportingAncestryTests(); void ReportingRecordTests(); void ReportingLogTests(); void ReportingRuntimeTests(); }
int main() {
    ReportingConfigTests();
    ReportingStateTests();
    ReportingJsonTests();
    rs2fix::testcases::ReportingProfileTests();
    ReportingSourceTests();
    ReportingStatusTests();
    rs2fix::testcases::ReportingAncestryTests();
    ReportingPreparedTests();
    ReportingCaptureTests();
    ReportingTaskTests();
    ReportingClientTests();
    rs2fix::testcases::ReportingLogTests();
    rs2fix::testcases::ReportingRuntimeTests();
    ReportingForwardTests();
    rs2fix::testcases::ReportingRecordTests();
    std::cout << "reporting checks=" << rs2fix::test::g_checks
        << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures ? 1 : 0;
}

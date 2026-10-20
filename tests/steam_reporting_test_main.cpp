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
namespace rs2fix::testcases { void NativeLogFramingTests(); }
namespace rs2fix::testcases { void NativeLogSourceTests(); }
namespace rs2fix::testcases { void NativeLogFormatTests(); }
namespace rs2fix::testcases { void NativeLogReceiptTests(); }
namespace rs2fix::testcases { void NativeLogPipelineTests(); }
namespace rs2fix::testcases { void NativeLogFileTests(); }
namespace rs2fix::testcases { void NativeLogServiceTests(); }
namespace rs2fix::testcases { void ReportingConsoleTests(); }
namespace rs2fix::testcases { void RecoveryWireTests(); void LeechRecoveryPolicyTests();
    void LeechRecoveryNativeTests(); void RunLeechRecoveryControlTests(); void LeechRecoveryTests(); }
int main() {
    rs2fix::testcases::RecoveryWireTests();
    rs2fix::testcases::LeechRecoveryPolicyTests();
    rs2fix::testcases::LeechRecoveryNativeTests();
    rs2fix::testcases::RunLeechRecoveryControlTests();
    rs2fix::testcases::LeechRecoveryTests();
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
    rs2fix::testcases::NativeLogFramingTests();
    rs2fix::testcases::NativeLogSourceTests();
    rs2fix::testcases::NativeLogFormatTests();
    rs2fix::testcases::NativeLogReceiptTests();
    rs2fix::testcases::NativeLogPipelineTests();
    rs2fix::testcases::NativeLogFileTests();
    rs2fix::testcases::NativeLogServiceTests();
    rs2fix::testcases::ReportingConsoleTests();
    std::cout << "reporting checks=" << rs2fix::test::g_checks
        << " failures=" << rs2fix::test::g_failures << '\n';
    return rs2fix::test::g_failures ? 1 : 0;
}

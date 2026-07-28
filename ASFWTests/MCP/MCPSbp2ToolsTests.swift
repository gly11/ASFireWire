import Testing
@testable import ASFW

struct MCPSbp2ToolsTests {
    private func config(
        _ mode: ASFWMCPRuntimeMode,
        writePolicyAvailable: Bool = false,
        swiftTestGatePassed: Bool = false,
        rawDeveloperTierEnabled: Bool = false
    ) -> ASFWMCPRuntimeConfiguration {
        ASFWMCPRuntimeConfiguration(
            mode: mode,
            writePolicyAvailable: writePolicyAvailable,
            swiftTestGatePassed: swiftTestGatePassed,
            rawDeveloperTierEnabled: rawDeveloperTierEnabled
        )
    }

    private var gateOpen: ASFWMCPRuntimeConfiguration {
        config(.developerWriteEnabled, writePolicyAvailable: true, swiftTestGatePassed: true)
    }

    private var gateOpenRawTier: ASFWMCPRuntimeConfiguration {
        config(.developerWriteEnabled, writePolicyAvailable: true, swiftTestGatePassed: true, rawDeveloperTierEnabled: true)
    }

    private func unitAddress() -> ASFWMCPAddress {
        ASFWMCPAddress(nodeId: 2, generation: 17, addressHigh: 0xFFFF, addressLow: 0xF0000800)
    }

    private func toolNames(_ cfg: ASFWMCPRuntimeConfiguration) async -> Set<String> {
        let core = ASFWMCPCore(configuration: cfg, driver: MockASFWDriverControl(nodes: [MockASFWDriverControl.sbp2Node]))
        return await Set(core.listTools().map(\.name))
    }

    private func object(_ result: ASFWMCPToolCallResult) -> [String: ASFWMCPValue] {
        guard case .object(let object) = result.data else {
            Issue.record("Expected tool result data to be an object.")
            return [:]
        }
        return object
    }

    private func decide(_ cfg: ASFWMCPRuntimeConfiguration, _ req: ASFWMCPPolicyRequest) -> ASFWMCPPolicyDecision {
        ASFWMCPWritePolicyEngine(configuration: cfg).evaluate(req)
    }

    @Test func inspectionToolsHiddenWithoutSbp2Node() async {
        let core = ASFWMCPCore(configuration: config(.readOnlyDeveloper), driver: MockASFWDriverControl(nodes: MockASFWDriverControl.defaultNodes))
        let names = await Set(core.listTools().map(\.name))
        #expect(names.contains("asfw_sbp2_list_units") == false)
        #expect(names.contains("asfw_sbp2_inspect_unit") == false)
    }

    @Test func inspectionToolsListAndMutationsHiddenInReadOnly() async {
        let names = await toolNames(config(.readOnlyDeveloper))
        #expect(names.isSuperset(of: ["asfw_sbp2_list_units", "asfw_sbp2_inspect_unit", "asfw_sbp2_get_session_status"]))
        #expect(names.contains("asfw_sbp2_login_dev") == false)
        #expect(names.contains("asfw_sbp2_submit_orb_dev") == false)
    }

    @Test func mutationsRemainHiddenWithoutRawTierEvenWhenGateOpen() async {
        let names = await toolNames(gateOpen)
        #expect(names.contains("asfw_sbp2_login_dev") == false)
        #expect(names.contains("asfw_sbp2_submit_orb_dev") == false)
    }

    @Test func mutationsListWhenRawTierEnabled() async {
        let names = await toolNames(gateOpenRawTier)
        #expect(names.isSuperset(of: ["asfw_sbp2_login_dev", "asfw_sbp2_submit_orb_dev"]))
    }

    @Test func sessionStatesCoverInspectionOutcomes() {
        #expect(ASFWMCPSbp2SessionState.allCases.count == 5)
        let active = ASFWMCPSbp2SessionStatus(nodeId: 2, state: .active, loginId: 7)
        #expect(active.state == .active)
        #expect(active.loginId == 7)
        #expect(ASFWMCPSbp2SessionStatus(nodeId: 2, state: .absent).loginId == nil)
    }

    @Test func listUnitsReturnsDiscoveredUnitDirectoryEvidenceWithoutWrites() async {
        let driver = MockASFWDriverControl(nodes: [MockASFWDriverControl.sbp2Node])
        let core = ASFWMCPCore(configuration: .readOnlyDeveloper, driver: driver)

        let result = await core.callTool(name: "asfw_sbp2_list_units")
        let data = object(result)

        #expect(result.ok)
        #expect(data["kind"] == .string("sbp2UnitInventory"))
        guard case .array(let units)? = data["units"],
              case .object(let unit)? = units.first else {
            Issue.record("Expected one decoded SBP-2 unit.")
            return
        }
        #expect(unit["guid"] == .string("0x0022334455667788"))
        #expect(unit["nodeId"] == .int(2))
        #expect(unit["specifierId"] == .string("0x00609E"))
        #expect(unit["softwareVersion"] == .string("0x010483"))
        #expect(unit["managementAgentOffset"] == .string("0x00000100"))
        #expect(unit["commandSet"] == .string("SCSI"))
        #expect(await driver.unexpectedWriteAttemptCount() == 0)
    }

    @Test func inspectUnitRequiresAUnitInTheCurrentDiscoverySnapshot() async {
        let driver = MockASFWDriverControl(nodes: [MockASFWDriverControl.sbp2Node])
        let core = ASFWMCPCore(configuration: .readOnlyDeveloper, driver: driver)

        let found = await core.callTool(
            name: "asfw_sbp2_inspect_unit",
            arguments: .object([
                "targetGuid": .uint64(0x0022_3344_5566_7788),
                "romOffset": .int(0),
            ])
        )
        let missing = await core.callTool(
            name: "asfw_sbp2_inspect_unit",
            arguments: .object([
                "targetGuid": .uint64(0xDEAD_BEEF_0000_0001),
                "romOffset": .int(0),
            ])
        )

        #expect(found.ok)
        #expect(object(found)["kind"] == .string("sbp2UnitInspection"))
        #expect(missing.ok == false)
        #expect(missing.errors.first?.code == .capabilityUnavailable)
        #expect(await driver.unexpectedWriteAttemptCount() == 0)
    }

    @Test func sessionStatusReportsMissingCrossOwnerSnapshotCapability() async {
        let driver = MockASFWDriverControl(nodes: [MockASFWDriverControl.sbp2Node])
        let core = ASFWMCPCore(configuration: .readOnlyDeveloper, driver: driver)

        let result = await core.callTool(name: "asfw_sbp2_get_session_status")

        #expect(result.ok == false)
        #expect(result.errors.first?.code == .capabilityUnavailable)
        #expect(result.errors.first?.reason.contains("cross-owner session snapshot") == true)
        #expect(await driver.unexpectedWriteAttemptCount() == 0)
    }

    @Test func orbValidationRejectsEmptyUnalignedAndOversize() {
        #expect(ASFWMCPSbp2OrbRequest(address: unitAddress(), orb: [0, 0, 0, 0]).validationError == nil)
        #expect(ASFWMCPSbp2OrbRequest(address: unitAddress(), orb: []).validationError == .malformedRequest)
        #expect(ASFWMCPSbp2OrbRequest(address: unitAddress(), orb: [1, 2, 3]).validationError == .malformedRequest)
        #expect(ASFWMCPSbp2OrbRequest(address: unitAddress(), orb: [UInt8](repeating: 0, count: 4096)).validationError == .payloadTooLarge)
    }

    @Test func loginIsDeniedWithoutRawTierAndAllowedWithIt() {
        let request = ASFWMCPSbp2LoginRequest(address: unitAddress())
        let withoutTier = decide(gateOpen, request.policyRequest(currentGeneration: 17))
        #expect(withoutTier.decision == .denied)
        #expect(withoutTier.requiredCapability == "rawDeveloperTier")

        let withTier = decide(gateOpenRawTier, request.policyRequest(currentGeneration: 17))
        #expect(withTier.decision == .allowed)
    }
}

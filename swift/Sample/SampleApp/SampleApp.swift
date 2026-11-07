import NetworkExtension
import SwiftUI

@main
struct SampleApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

enum Proto: String, CaseIterable, Identifiable {
    case awg
    case xray

    var id: String { rawValue }
}

struct ContentView: View {
    static let providerBundleId = "org.amnezia.sample.PacketTunnel"

    @AppStorage("proto") private var proto: Proto = .awg
    @AppStorage("conf") private var conf = ""

    var body: some View {
        VStack {
            Picker("Protocol", selection: $proto) {
                ForEach(Proto.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            TextEditor(text: $conf)
                .font(.body.monospaced())
                .autocorrectionDisabled()

            HStack {
                Button("Start") { Task { await start() } }
                Button("Stop") { Task { await stop() } }
            }
        }
        .padding()
    }

    private func start() async {
        do {
            let manager = try await Self.loadManager() ?? NETunnelProviderManager()

            let config = NETunnelProviderProtocol()
            config.providerBundleIdentifier = Self.providerBundleId
            config.serverAddress = "xtun"
            config.providerConfiguration = ["proto": proto.rawValue, "conf": conf]

            manager.protocolConfiguration = config
            manager.localizedDescription = "xtun sample"
            manager.isEnabled = true

            try await manager.saveToPreferences()
            try await manager.loadFromPreferences()
            try manager.connection.startVPNTunnel()
        } catch {
            print("start failed: \(error)")
        }
    }

    private func stop() async {
        try? await Self.loadManager()?.connection.stopVPNTunnel()
    }

    private static func loadManager() async throws -> NETunnelProviderManager? {
        try await NETunnelProviderManager.loadAllFromPreferences().first
    }
}

#Preview {
    ContentView()
}

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdmd.hpp"

#include "mctp_transport_discovery.hpp"
#include "spdm_dbus_responder.hpp"
#include "spdm_discovery.hpp"
#include "tcp_transport_discovery.hpp"

#include <sdbusplus/async.hpp>
#include <sdbusplus/server/manager.hpp>

#include <cstdint>

int main()
{
    using namespace spdm;

    // Create async context for parallel coroutine execution
    sdbusplus::async::context ctx;

    // Create object manager for D-Bus object registration
    sdbusplus::server::manager_t objManager(ctx, objManagerPath);

    SPDMDiscovery discovery{};

    // Start MCTP discovery
    MCTPTransportDiscovery mctp{ctx};
    discovery.discover(mctp);

    // Start TCP discovery
    TCPTransportDiscovery tcp{ctx};
    discovery.discover(tcp);

    std::vector<std::unique_ptr<SPDMDBusResponder>> responders;

    // Run the initial discovery, create D-Bus responders, claim the bus
    // name, then perform eager attestation in a separate coroutine.
    //
    // The bus name is claimed BEFORE attestation so that systemd considers
    // the service "started" immediately. Attestation may take a long time
    // for unreachable devices (libspdm retries with socket timeouts), and
    // we don't want that to block systemd's start operation.
    ctx.spawn([&]() -> sdbusplus::async::task<> {
        co_await discovery.run();

        for (const auto& device : discovery.devices())
        {
            responders.push_back(
                std::make_unique<SPDMDBusResponder>(ctx, device));
        }

        // Request D-Bus name after initial discovery so the service is
        // visible to clients before attestation completes.
        ctx.request_name(dbusServiceName);

        // Perform eager attestation as best-effort: failures set
        // VerificationStatus::Failed on D-Bus but do not prevent the
        // responder from being exposed.
        for (auto& responder : responders)
        {
            responder->performEagerAttestation();
        }
    }());

    // Run the sdbusplus async context for parallel coroutine execution
    ctx.run();

    return EXIT_SUCCESS;
}

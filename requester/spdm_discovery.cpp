// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_discovery.hpp"

#include "spdm_responder_manager.hpp"

#include <phosphor-logging/lg2.hpp>
#include <sdbusplus/async.hpp>

namespace spdm
{

SPDMDiscovery::SPDMDiscovery() {}

auto SPDMDiscovery::run() -> sdbusplus::async::task<>
{
    PHOSPHOR_LOG2_USING;

    co_await initialDiscovery.on_empty();
    debug("SPDMDiscovery: initial discovery complete.");

    // Check results.
    if (!responderInfos.empty())
    {
        // Log discovered devices
        for (const auto& device : responderInfos)
        {
            info("Found SPDM device: PATH={PATH}", "PATH", device.path);
        }
    }
    else
    {
        warning("No SPDM devices found");
    }
}

void SPDMDiscovery::add(ResponderInfo&& r, bool isRuntimeDiscovered)
{
    PHOSPHOR_LOG2_USING;

    // Delete-recreate: if the same D-Bus path arrives again (e.g., via
    // a runtime InterfacesAdded signal after the initial mapper sweep,
    // or via a matcher that re-fires for the same object), replace
    // the existing entry rather than ignoring the new one.  A re-add
    // may represent a fresh device state — firmware update, reset, or
    // a compromise scenario — that should not inherit cached
    // attestation state.  Force fresh attestation every time, even at
    // the cost of re-attesting an unchanged device.
    auto path = r.path;
    auto wasReplaced = std::erase_if(responderInfos, [&path](const auto& e) {
        return e.path == path;
    });
    if (wasReplaced > 0)
    {
        debug("SPDMDiscovery: replacing existing entry for {PATH}", "PATH",
              path);
    }

    responderInfos.emplace_back(std::move(r));

    if (isRuntimeDiscovered && responderManager)
    {
        // Notify the responder manager about the newly added device
        const auto& lastDevice = responderInfos.back();
        responderManager->notifyDeviceAdded(lastDevice);
    }
}

void SPDMDiscovery::remove(const sdbusplus::message::object_path& path)
{
    std::erase_if(responderInfos,
                  [&path](const auto& r) { return r.path == path; });

    if (responderManager)
    {
        responderManager->notifyDeviceRemoved(path);
    }
}

} // namespace spdm

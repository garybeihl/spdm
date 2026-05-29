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

    // Dedup. The same D-Bus path can arrive via both the initial mapper
    // sweep and a runtime InterfacesAdded signal, or via a matcher that
    // fires more than once for the same object. Without this guard each
    // call would spawn a fresh per-device coroutine racing on the same
    // MCTP socket.
    for (const auto& existing : responderInfos)
    {
        if (existing.path == r.path)
        {
            debug("SPDMDiscovery: ignoring duplicate add for {PATH}", "PATH",
                  r.path);
            return;
        }
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

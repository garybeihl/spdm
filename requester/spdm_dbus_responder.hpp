// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "component_integrity_dbus.hpp"
#include "spdm_discovery.hpp"
#include "trusted_component_dbus.hpp"

#include <sdbusplus/async.hpp>

#include <memory>
#include <string>

namespace spdm
{

/**
 * @brief D-Bus responder object for a discovered SPDM device.
 * @details Owns the ComponentIntegrity and TrustedComponent D-Bus interface
 *          objects that represent the device on the bus, and runs SPDM
 *          attestation asynchronously after construction.
 */
class SPDMDBusResponder
{
  public:
    SPDMDBusResponder() = delete;
    SPDMDBusResponder(const SPDMDBusResponder&) = delete;
    SPDMDBusResponder& operator=(const SPDMDBusResponder&) = delete;
    SPDMDBusResponder(SPDMDBusResponder&&) = delete;
    SPDMDBusResponder& operator=(SPDMDBusResponder&&) = delete;

    /**
     * @brief Construct a new SPDM D-Bus Responder
     * @param ctx Reference to the async context for D-Bus operations
     * @param responderInfo ResponderInfo containing device details
     */
    explicit SPDMDBusResponder(sdbusplus::async::context& ctx,
                               const ResponderInfo& responderInfo);

    ~SPDMDBusResponder() = default;

    /**
     * @brief Perform async operations for this responder
     * @details Contains the async logic for device connection and attestation.
     *          The manager is responsible for spawning this coroutine.
     * @return Async task for coroutine execution
     */
    auto run() -> sdbusplus::async::task<>;

  private:
    sdbusplus::async::context& asyncCtx;
    ResponderInfo responderInfo;
    std::string deviceName;
    std::unique_ptr<ComponentIntegrity> componentIntegrity;
    std::unique_ptr<TrustedComponent> trustedComponent;
};

} // namespace spdm

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#pragma once

#include "component_integrity_dbus.hpp"
#include "libspdm_transport.hpp"
#include "spdm_discovery.hpp"
#include "trusted_component_dbus.hpp"

#include <sdbusplus/async.hpp>

#include <memory>
#include <string>

namespace spdm
{

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
     * @param ctx Async context for parallel coroutine execution
     * @param info ResponderInfo containing device details
     */
    SPDMDBusResponder(sdbusplus::async::context& ctx,
                      const ResponderInfo& responderInfo);

    virtual ~SPDMDBusResponder() = default;

    /**
     * @brief Perform eager attestation on the device.
     *
     * Initializes the SPDM transport, then runs:
     *   1. VCA (GET_VERSION + GET_CAPABILITIES + NEGOTIATE_ALGORITHMS)
     *   2. GET_DIGESTS
     *   3. GET_CERTIFICATE
     *
     * Updates D-Bus properties with the negotiated SPDM version and
     * sets VerificationStatus to Success or Failed.
     *
     * @return true if attestation passed, false otherwise
     */
    bool performEagerAttestation();

    /** @brief Device name */
    std::string deviceName;

    /** @brief Associated inventory object path */
    std::string inventoryPath;

    std::unique_ptr<ComponentIntegrity> componentIntegrity;
    std::unique_ptr<TrustedComponent> trustedComponent;

  private:
    /** @brief SPDM transport for this device */
    std::shared_ptr<SpdmTransport> transport;
};

} // namespace spdm

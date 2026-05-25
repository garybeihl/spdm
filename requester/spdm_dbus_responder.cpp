// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include "libspdm_mctp_transport.hpp"

extern "C"
{
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_return_status.h"
}

#include <phosphor-logging/lg2.hpp>

PHOSPHOR_LOG2_USING;

namespace spdm
{

SPDMDBusResponder::SPDMDBusResponder(sdbusplus::async::context& ctx,
                                     const ResponderInfo& respInfo) :
    asyncCtx(ctx), responderInfo(respInfo)
{
    std::visit(
        [this](const auto& responder) {
            using T = std::decay_t<decltype(responder)>;

            if constexpr (std::is_same_v<T, MctpResponderInfo>)
            {
                deviceName = std::to_string(responder.eid);
                transport = std::make_shared<SpdmMctpTransport>(responder.eid);
            }
            else
            {
                deviceName = responder.ipAddr;
            }
        },
        responderInfo.info);

    std::string componentIntegrityPath =
        "/xyz/openbmc_project/ComponentIntegrity/" + deviceName;
    componentIntegrity =
        std::make_unique<ComponentIntegrity>(asyncCtx, componentIntegrityPath);

    std::string trustedComponentPath =
        "/xyz/openbmc_project/TrustedComponent/" + deviceName;
    trustedComponent = std::make_unique<TrustedComponent>(asyncCtx.get_bus(),
                                                          trustedComponentPath);

    info("Created SPDM D-Bus responder for device {ID} at {PATH}", "ID",
         deviceName, "PATH", responderInfo.path);
}

auto SPDMDBusResponder::run() -> sdbusplus::async::task<>
{
    debug("Running SPDM attestation for device {ID}", "ID", deviceName);

    if (!transport)
    {
        error("Attestation skipped for device {ID}: no transport (non-MCTP "
              "transports are not yet implemented in this branch)",
              "ID", deviceName);
        co_return;
    }

    // Step 1: Initialize SPDM transport + on-wire VCA.
    // transport->initialize() does local setup (libspdm context, callbacks,
    // scratch buffer, algorithm config). libspdm_init_connection() does the
    // on-wire GET_VERSION + GET_CAPABILITIES + NEGOTIATE_ALGORITHMS exchange.
    if (!transport->initialize())
    {
        error("Attestation FAILED for device {ID}: transport init failed",
              "ID", deviceName);
        co_return;
    }

    libspdm_return_t status =
        libspdm_init_connection(transport->spdmContext, false);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("Attestation FAILED for device {ID}: VCA status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        co_return;
    }

    // Step 2: GET_DIGESTS
    uint8_t slotMask = 0;
    constexpr size_t maxSlots = 8;
    constexpr size_t digestSize = 48;
    std::vector<uint8_t> digestBuffer(maxSlots * digestSize);
    status = libspdm_get_digest(transport->spdmContext, nullptr, &slotMask,
                                digestBuffer.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error(
            "Attestation FAILED for device {ID}: GET_DIGESTS status 0x{STATUS:x}",
            "ID", deviceName, "STATUS", status);
        co_return;
    }

    // Step 3: GET_CERTIFICATE slot 0
    std::vector<uint8_t> certChain(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    size_t certChainSize = certChain.size();
    status = libspdm_get_certificate(transport->spdmContext, nullptr, 0,
                                     &certChainSize, certChain.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("Attestation FAILED for device {ID}: "
              "GET_CERTIFICATE status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        co_return;
    }

    // CHALLENGE between Step 3 and Step 4. The responder signs a nonce with
    // its private key; libspdm verifies the signature against the public key
    // from the cert chain. Without CHALLENGE, a device with a stolen cert
    // and the wrong private key would still pass attestation. Per Ratan's
    // ML guidance in 038591, CHALLENGE belongs in eager attestation even
    // though it is optional in SPDM 1.1.
    status = libspdm_challenge(transport->spdmContext, nullptr, 0, 0, nullptr,
                               nullptr);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error(
            "Attestation FAILED for device {ID}: CHALLENGE status 0x{STATUS:x}",
            "ID", deviceName, "STATUS", status);
        co_return;
    }

    // Step 4: GET_MEASUREMENTS — request total measurement count.
    // A future patch will extend this to retrieve specific records once the
    // SignedMeasurements D-Bus surface lands (Gerrit 77349a9 follow-on).
    uint32_t measurementRecordLength = 0;
    std::vector<uint8_t> measurementRecord(LIBSPDM_MAX_MEASUREMENT_RECORD_SIZE);
    uint8_t numberOfBlocks = 0;
    status = libspdm_get_measurement(
        transport->spdmContext, nullptr, 0,
        SPDM_GET_MEASUREMENTS_REQUEST_MEASUREMENT_OPERATION_TOTAL_NUMBER_OF_MEASUREMENTS,
        0, 0, &numberOfBlocks, &measurementRecordLength,
        measurementRecord.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("Attestation FAILED for device {ID}: "
              "GET_MEASUREMENTS status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        co_return;
    }

    // Step 5: Update TrustedComponent D-Bus state.
    // MCTP responder = Integrated, TCP responder = Discrete.
    // ComponentIntegrity property updates (responder_verification_status,
    // type_version) are deferred until the Digest/Certificate D-Bus
    // commits are integrated.
    std::string componentType = "Integrated";
    std::visit(
        [&componentType](const auto& info) {
            using T = std::decay_t<decltype(info)>;
            if constexpr (std::is_same_v<T, TcpResponderInfo>)
            {
                componentType = "Discrete";
            }
        },
        responderInfo.info);
    trustedComponent->updateTrustedComponentType(componentType);

    info("Attestation PASSED for device {ID}: {BLOCKS} measurement blocks",
         "ID", deviceName, "BLOCKS", numberOfBlocks);
    co_return;
}

} // namespace spdm

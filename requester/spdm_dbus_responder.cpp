// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include "libspdm_mctp_transport.hpp"

extern "C"
{
#include "internal/libspdm_common_lib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_return_status.h"
}

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Attestation/IdentityAuthentication/common.hpp>

PHOSPHOR_LOG2_USING;

namespace spdm
{

using VerificationStatus = sdbusplus::common::xyz::openbmc_project::
    attestation::IdentityAuthentication::VerificationStatus;

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
    if (transport)
    {
        componentIntegrity->setTransport(transport);
    }

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
        error("attestation skipped for device {ID}: no transport (non-MCTP "
              "transports are not yet implemented in this branch)",
              "ID", deviceName);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        co_return;
    }

    // Step 1: Initialize SPDM transport + on-wire VCA.
    // transport->initialize() does local setup (libspdm context, callbacks,
    // scratch buffer, algorithm config). libspdm_init_connection() does the
    // on-wire GET_VERSION + GET_CAPABILITIES + NEGOTIATE_ALGORITHMS exchange.
    if (!transport->initialize())
    {
        error("attestation FAILED for device {ID}: transport init failed",
              "ID", deviceName);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        co_return;
    }

    libspdm_return_t status =
        libspdm_init_connection(transport->spdmContext, false);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("attestation FAILED for device {ID}: VCA status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        co_return;
    }

    // Extract negotiated SPDM version from libspdm context and publish on
    // the ComponentIntegrity.TypeVersion D-Bus property.
    auto* spdmCtx =
        reinterpret_cast<libspdm_context_t*>(transport->spdmContext);
    uint8_t versionByte = static_cast<uint8_t>(
        spdmCtx->connection_info.version >> SPDM_VERSION_NUMBER_SHIFT_BIT);
    uint8_t major = (versionByte >> 4) & 0x0F;
    uint8_t minor = versionByte & 0x0F;
    std::string versionStr =
        std::to_string(major) + "." + std::to_string(minor);
    componentIntegrity->type_version(versionStr);

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
            "attestation FAILED for device {ID}: GET_DIGESTS status 0x{STATUS:x}",
            "ID", deviceName, "STATUS", status);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        co_return;
    }

    // Step 3: GET_CERTIFICATE slot 0
    std::vector<uint8_t> certChain(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    size_t certChainSize = certChain.size();
    status = libspdm_get_certificate(transport->spdmContext, nullptr, 0,
                                     &certChainSize, certChain.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("attestation FAILED for device {ID}: "
              "GET_CERTIFICATE status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
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
            "attestation FAILED for device {ID}: CHALLENGE status 0x{STATUS:x}",
            "ID", deviceName, "STATUS", status);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        co_return;
    }

    // Step 4: GET_MEASUREMENTS — request total measurement count.
    // On-demand SignedMeasurements retrieval happens via the
    // ComponentIntegrity.SPDMGetSignedMeasurements D-Bus method (from the
    // 77349a9 commit), so eager attestation only proves the responder
    // supports measurements without pulling them all.
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
        error("attestation FAILED for device {ID}: "
              "GET_MEASUREMENTS status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        co_return;
    }

    // Step 5: Update both D-Bus surfaces on success.
    // MCTP responder = Integrated, TCP responder = Discrete.
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
    componentIntegrity->responder_verification_status(
        VerificationStatus::Success);

    info("attestation PASSED for device {ID}: SPDM {VERSION}, {BLOCKS} "
         "measurement blocks",
         "ID", deviceName, "VERSION", versionStr, "BLOCKS", numberOfBlocks);
    co_return;
}

} // namespace spdm

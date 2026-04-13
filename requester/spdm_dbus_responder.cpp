// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include "libspdm_mctp_transport.hpp"
#include "spdmd.hpp"

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

SPDMDBusResponder::SPDMDBusResponder(sdbusplus::async::context& ctx,
                                     const ResponderInfo& responderInfo) :
    inventoryPath(responderInfo.path.str)
{
    std::visit(
        [this](const auto& responder) {
            using T = std::decay_t<decltype(responder)>;

            if constexpr (std::is_same_v<T, MctpResponderInfo>)
            {
                deviceName = std::to_string(responder.eid);
            }
            else
            {
                deviceName = responder.ipAddr;
            }
        },
        responderInfo.info);

    std::string componentIntegrityPath =
        std::string(objManagerPath) + "/" + deviceName;
    componentIntegrity =
        std::make_unique<ComponentIntegrity>(ctx, componentIntegrityPath);
    std::visit(
        [this](const auto& info) {
            using T = std::decay_t<decltype(info)>;
            if constexpr (std::is_same_v<T, MctpResponderInfo>)
            {
                transport = std::make_shared<SpdmMctpTransport>(info.eid);
                componentIntegrity->setTransport(transport);
            }
        },
        responderInfo.info);

    std::string trustedComponentPath =
        "/xyz/openbmc_project/TrustedComponent/" + deviceName;
    trustedComponent =
        std::make_unique<TrustedComponent>(ctx, trustedComponentPath);

    info("Created SPDM D-Bus responder for device {ID} at {PATH}", "ID",
         deviceName, "PATH", responderInfo.path);
}

bool SPDMDBusResponder::performEagerAttestation()
{
    using VerificationStatus = sdbusplus::common::xyz::openbmc_project::
        attestation::IdentityAuthentication::VerificationStatus;

    if (!transport)
    {
        error("Eager attestation skipped for device {ID}: no transport", "ID",
              deviceName);
        return false;
    }

    // Initialize the SPDM transport (context, callbacks, scratch buffer)
    if (!transport->initialize())
    {
        error("Eager attestation FAILED for device {ID}: "
              "transport initialization failed",
              "ID", deviceName);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        return false;
    }

    // Step 1: VCA — GET_VERSION + GET_CAPABILITIES + NEGOTIATE_ALGORITHMS
    libspdm_return_t status =
        libspdm_init_connection(transport->spdmContext, false);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("Eager attestation FAILED for device {ID}: "
              "VCA failed, status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        return false;
    }

    // Extract negotiated SPDM version and update D-Bus property
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
    constexpr size_t digestSize = 48;
    constexpr size_t maxSlots = 8;
    std::vector<uint8_t> digestBuffer(maxSlots * digestSize);

    status = libspdm_get_digest(transport->spdmContext, nullptr, &slotMask,
                                digestBuffer.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("Eager attestation FAILED for device {ID}: "
              "GET_DIGESTS failed, status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        return false;
    }

    // Step 3: GET_CERTIFICATE (slot 0)
    std::vector<uint8_t> certChain(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    size_t certChainSize = certChain.size();
    status = libspdm_get_certificate(transport->spdmContext, nullptr, 0,
                                     &certChainSize, certChain.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("Eager attestation FAILED for device {ID}: "
              "GET_CERTIFICATE failed, status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        return false;
    }

    // Step 4: CHALLENGE — the responder signs a nonce with its private key;
    // libspdm verifies the signature against the public key from the cert.
    // This detects key mismatch (wrong/compromised private key).
    status = libspdm_challenge(transport->spdmContext, nullptr, 0, 0, nullptr,
                               nullptr);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("Eager attestation FAILED for device {ID}: "
              "CHALLENGE failed, status 0x{STATUS:x}",
              "ID", deviceName, "STATUS", status);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        return false;
    }

    info("Eager attestation PASSED for device {ID}, SPDM version {VERSION}",
         "ID", deviceName, "VERSION", versionStr);
    componentIntegrity->responder_verification_status(
        VerificationStatus::Success);
    return true;
}

} // namespace spdm

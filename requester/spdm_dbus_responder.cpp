// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "spdm_dbus_responder.hpp"

#include "libspdm_mctp_transport.hpp"
#include "libspdm_tcp_transport.hpp"
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

#include <algorithm>

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
                // D-Bus object paths cannot contain dots, so sanitize the
                // IP address before using it as a path component. Append
                // the port to disambiguate multiple responders at the
                // same address. Example:
                //   ipAddr = "10.0.2.2", port = 2323
                //     -> deviceName = "10_0_2_2_2323"
                //     -> path = "/xyz/openbmc_project/SPDM/10_0_2_2_2323"
                deviceName = responder.ipAddr;
                std::replace(deviceName.begin(), deviceName.end(), '.', '_');
                std::replace(deviceName.begin(), deviceName.end(), ':', '_');
                deviceName += "_" + std::to_string(responder.port);
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
            else if constexpr (std::is_same_v<T, TcpResponderInfo>)
            {
                transport = std::make_shared<SpdmTcpTransport>(
                    info.ipAddr, static_cast<uint16_t>(info.port));
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
    // Buffer must be LIBSPDM_MAX_SLOT_COUNT * LIBSPDM_MAX_HASH_SIZE so
    // libspdm can fill in slot-positioned digests for whatever hash
    // algorithm was negotiated (SHA-256 = 32B, SHA-384 = 48B,
    // SHA-512 = 64B per slot).  The previous hardcoded 48B per slot
    // matched SHA-384 but undersized for SHA-512; in practice libspdm
    // writes only negotiated-hashlen bytes per slot so SHA-256 still
    // fits, but defending against the SHA-512 case is correct.
    uint8_t slotMask = 0;
    std::vector<uint8_t> digestBuffer(SPDM_MAX_SLOT_COUNT *
                                      LIBSPDM_MAX_HASH_SIZE);

    status = libspdm_get_digest(transport->spdmContext, nullptr, &slotMask,
                                digestBuffer.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("Eager attestation FAILED for device {ID}: "
              "GET_DIGESTS failed, status 0x{STATUS}",
              "ID", deviceName, "STATUS", lg2::hex,
              static_cast<uint32_t>(status));
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

    // Step 5: GET_MEASUREMENTS with signature — the headline SPDM 1.2
    // attestation value-add.  The responder hashes its measurement
    // blocks (boot ROM, runtime firmware, etc.), signs the hash with
    // its private key, and returns the measurement record + signature.
    // libspdm verifies the signature against the cert chain from Step 3.
    //
    // Request all measurement blocks in one call (operation = 0xFF)
    // with signature attribute set; slot 0 matches the cert we fetched.
    {
        constexpr uint8_t allBlocksOperation = 0xFF;
        constexpr uint8_t slotId = 0;
        constexpr uint8_t requestAttributeSigned =
            SPDM_GET_MEASUREMENTS_REQUEST_ATTRIBUTES_GENERATE_SIGNATURE;
        constexpr uint32_t maxMeasurementSize = 4096;
        std::vector<uint8_t> measurementBuffer(maxMeasurementSize);
        uint32_t measurementSize = measurementBuffer.size();
        uint8_t contentChanged = 0;
        uint8_t numberOfBlocks = 0;

        status = libspdm_get_measurement(
            transport->spdmContext, nullptr, requestAttributeSigned,
            allBlocksOperation, slotId, &contentChanged, &numberOfBlocks,
            &measurementSize, measurementBuffer.data());
        if (LIBSPDM_STATUS_IS_ERROR(status))
        {
            error("Eager attestation FAILED for device {ID}: "
                  "Signed GET_MEASUREMENTS failed, status 0x{STATUS:x}",
                  "ID", deviceName, "STATUS", status);
            componentIntegrity->responder_verification_status(
                VerificationStatus::Failed);
            return false;
        }
        info("Signed GET_MEASUREMENTS for device {ID}: {COUNT} blocks, "
             "{SIZE} bytes",
             "ID", deviceName, "COUNT", numberOfBlocks, "SIZE",
             measurementSize);
    }

    info("Eager attestation PASSED for device {ID}, SPDM version {VERSION}",
         "ID", deviceName, "VERSION", versionStr);
    componentIntegrity->responder_verification_status(
        VerificationStatus::Success);
    return true;
}

} // namespace spdm

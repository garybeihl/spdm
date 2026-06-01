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
        "/xyz/openbmc_project/component_integrity/" + deviceName;
    componentIntegrity =
        std::make_unique<ComponentIntegrity>(asyncCtx, componentIntegrityPath);
    if (transport)
    {
        componentIntegrity->setTransport(transport);
    }

    // ComponentIntegrity multi-inherits from three separate aserver server_t
    // bases (ComponentIntegrity, MeasurementSet, IdentityAuthentication), one
    // per interface. The bases register their interfaces with sd-bus but do
    // not auto-emit org.freedesktop.DBus.ObjectManager.InterfacesAdded at
    // construction. bmcweb's per-id GET /redfish/v1/ComponentIntegrity/<id>
    // handler requires all three interfaces visible via getSubTree, which is
    // satisfied for boot-time objects (mapper has time to scan introspection
    // XML) but races for runtime-added objects when bmcweb queries shortly
    // after construction.
    //
    // Explicitly emit InterfacesAdded on each base, fully-qualified to
    // disambiguate emit_added among the inherited bases, so the mapper sees
    // all three atomically as soon as the object is constructed.
    using CIBase = sdbusplus::aserver::xyz::openbmc_project::attestation::
        ComponentIntegrity<spdm::ComponentIntegrity, void>;
    using MSBase =
        sdbusplus::aserver::xyz::openbmc_project::attestation::MeasurementSet<
            spdm::ComponentIntegrity, void>;
    using IABase = sdbusplus::aserver::xyz::openbmc_project::attestation::
        IdentityAuthentication<spdm::ComponentIntegrity, void>;
    static_cast<CIBase*>(componentIntegrity.get())->emit_added();
    static_cast<MSBase*>(componentIntegrity.get())->emit_added();
    static_cast<IABase*>(componentIntegrity.get())->emit_added();

    std::string trustedComponentPath =
        "/xyz/openbmc_project/inventory/trusted_component/" + deviceName;
    trustedComponent = std::make_unique<TrustedComponent>(
        asyncCtx.get_bus(), trustedComponentPath);

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
        error("attestation FAILED for device {ID}: transport init failed", "ID",
              deviceName);
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        co_return;
    }

    libspdm_return_t status =
        libspdm_init_connection(transport->spdmContext, false);
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("attestation FAILED for device {ID}: VCA status {STATUS}", "ID",
              deviceName, "STATUS", lg2::hex, static_cast<unsigned>(status));
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
        error("attestation FAILED for device {ID}: GET_DIGESTS status {STATUS}",
              "ID", deviceName, "STATUS", lg2::hex,
              static_cast<unsigned>(status));
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        co_return;
    }
    info("GET_DIGESTS for device {ID}: slotMask={MASK}", "ID", deviceName,
         "MASK", lg2::hex, static_cast<unsigned>(slotMask));

    // Step 3: GET_CERTIFICATE slot 0
    std::vector<uint8_t> certChain(LIBSPDM_MAX_CERT_CHAIN_SIZE);
    size_t certChainSize = certChain.size();
    status = libspdm_get_certificate(transport->spdmContext, nullptr, 0,
                                     &certChainSize, certChain.data());
    if (LIBSPDM_STATUS_IS_ERROR(status))
    {
        error("attestation FAILED for device {ID}: "
              "GET_CERTIFICATE status {STATUS}",
              "ID", deviceName, "STATUS", lg2::hex,
              static_cast<unsigned>(status));
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
        error("attestation FAILED for device {ID}: CHALLENGE status {STATUS}",
              "ID", deviceName, "STATUS", lg2::hex,
              static_cast<unsigned>(status));
        componentIntegrity->responder_verification_status(
            VerificationStatus::Failed);
        co_return;
    }

    // Step 4: GET_MEASUREMENTS — fetch the responder's measurement
    // state at eager-attestation time.  SPDMGetSignedMeasurements
    // belongs in the eager attestation path alongside the on-demand
    // ComponentIntegrity D-Bus method from commit 77349a9 — so that
    // measurement retrieval succeeds at attestation time, not only
    // when a Redfish client later queries it.
    //
    // Use measurement_operation = 0xFF to request all measurement
    // blocks in a single libspdm call, matching the on-demand path's
    // default behavior (indicesToProcess = {255}).
    {
        constexpr uint8_t allBlocksOperation = 0xFF;
        constexpr uint8_t slotId = 0;
        constexpr uint8_t requestAttribute = 0;
        constexpr size_t maxMeasurementSize = 4096;
        std::vector<uint8_t> measurementBuffer(maxMeasurementSize);
        uint32_t measurementSize = measurementBuffer.size();
        uint8_t contentChanged = 0;
        uint8_t numberOfBlocks = 0;

        status = libspdm_get_measurement(
            transport->spdmContext,
            nullptr, // No session
            requestAttribute, allBlocksOperation, slotId, &contentChanged,
            &numberOfBlocks, &measurementSize, measurementBuffer.data());
        if (LIBSPDM_STATUS_IS_ERROR(status))
        {
            error("attestation FAILED for device {ID}: "
                  "GET_MEASUREMENTS status {STATUS}",
                  "ID", deviceName, "STATUS", lg2::hex,
                  static_cast<unsigned>(status));
            componentIntegrity->responder_verification_status(
                VerificationStatus::Failed);
            co_return;
        }

        info("GET_MEASUREMENTS for device {ID}: {COUNT} blocks, {SIZE} bytes",
             "ID", deviceName, "COUNT", static_cast<unsigned>(numberOfBlocks),
             "SIZE", measurementSize);
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

    info("attestation PASSED for device {ID}: SPDM {VERSION}", "ID", deviceName,
         "VERSION", versionStr);
    co_return;
}

} // namespace spdm

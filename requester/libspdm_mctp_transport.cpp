// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "libspdm_mctp_transport.hpp"

#include <phosphor-logging/lg2.hpp>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace spdm
{

/**
 * @brief Trust-on-first-use certificate verification callback.
 *
 * Accepts any valid X.509 chain without requiring a pre-provisioned
 * root certificate. Production deployments should replace this with a
 * callback that checks the chain against a provisioned trust anchor.
 */
static bool tofuVerifyCertChain(
    void* /*spdmContext*/, uint8_t /*slotId*/, size_t /*certChainSize*/,
    const void* /*certChain*/, const void** trustAnchor,
    size_t* trustAnchorSize)
{
    if (trustAnchor != nullptr)
    {
        *trustAnchor = nullptr;
    }
    if (trustAnchorSize != nullptr)
    {
        *trustAnchorSize = 0;
    }
    return true;
}

bool SpdmMctpTransport::initialize()
{
    if (!mctpIo.createSocket())
    {
        lg2::error("Failed to create MCTP socket for EID {EID}", "EID", eid);
        return false;
    }
    if (!allocateContext())
    {
        return false;
    }

    if (!registerFunctions())
    {
        cleanupContext();
        return false;
    }

    if (!setupScratchBuffer())
    {
        cleanupContext();
        return false;
    }

    if (!configureContext())
    {
        cleanupContext();
        return false;
    }

    return true;
}

bool SpdmMctpTransport::allocateContext()
{
    spdmContext = static_cast<void*>(malloc(libspdm_get_context_size()));
    if (!spdmContext)
    {
        lg2::error("Failed to allocate SPDM context");
        return false;
    }

    libspdm_return_t status = libspdm_init_context(spdmContext);
    if (!spdmContext || status != LIBSPDM_STATUS_SUCCESS)
    {
        lg2::error("Failed to initialize SPDM context");
        return false;
    }

    libspdm_context_t* context = static_cast<libspdm_context_t*>(spdmContext);
    context->app_context_data_ptr = this;
    return true;
}

bool SpdmMctpTransport::registerFunctions()
{
    libspdm_register_device_io_func(spdmContext,
                                    &SpdmMctpTransport::device_send_message,
                                    &SpdmMctpTransport::device_receive_message);
    libspdm_register_transport_layer_func(
        spdmContext, LIBSPDM_MAX_SPDM_MSG_SIZE, LIBSPDM_TRANSPORT_HEADER_SIZE,
        LIBSPDM_TRANSPORT_TAIL_SIZE, libspdm_transport_mctp_encode_message,
        libspdm_transport_mctp_decode_message);
    libspdm_register_device_buffer_func(
        spdmContext, LIBSPDM_SENDER_BUFFER_SIZE, LIBSPDM_RECEIVER_BUFFER_SIZE,
        &SpdmMctpTransport::spdm_device_acquire_sender_buffer,
        &SpdmMctpTransport::spdm_device_release_sender_buffer,
        &SpdmMctpTransport::spdm_device_acquire_receiver_buffer,
        &SpdmMctpTransport::spdm_device_release_receiver_buffer);
    return true;
}

bool SpdmMctpTransport::setupScratchBuffer()
{
    size_t scratch_buffer_size =
        libspdm_get_sizeof_required_scratch_buffer(spdmContext);
    scratchBuffer = malloc(scratch_buffer_size);
    if (scratchBuffer == nullptr)
    {
        return false;
    }

    libspdm_set_scratch_buffer(spdmContext, scratchBuffer, scratch_buffer_size);
    if (!libspdm_check_context(spdmContext))
    {
        lg2::error("Context check failed");
        return false;
    }
    return true;
}

bool SpdmMctpTransport::configureContext()
{
    // Register trust-on-first-use certificate verification so that
    // libspdm_get_certificate() succeeds without a pre-provisioned
    // root cert. TODO: replace with Entity Manager trust anchor lookup.
    libspdm_register_verify_spdm_cert_chain_func(spdmContext,
                                                  tofuVerifyCertChain);

    libspdm_zero_mem(&parameter, sizeof(parameter));
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;

    // Register all supported SPDM versions so libspdm negotiates the
    // highest common version with the responder.
    spdm_version_number_t versions[] = {
        SPDM_MESSAGE_VERSION_10 << SPDM_VERSION_NUMBER_SHIFT_BIT,
        SPDM_MESSAGE_VERSION_11 << SPDM_VERSION_NUMBER_SHIFT_BIT,
        SPDM_MESSAGE_VERSION_12 << SPDM_VERSION_NUMBER_SHIFT_BIT,
    };
    libspdm_set_data(spdmContext, LIBSPDM_DATA_SPDM_VERSION, &parameter,
                     versions, sizeof(versions));

    // Requester capabilities: certificate retrieval and challenge
    uint32_t capFlags = SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CERT_CAP |
                        SPDM_GET_CAPABILITIES_REQUEST_FLAGS_CHAL_CAP;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_CAPABILITY_FLAGS, &parameter,
                     &capFlags, sizeof(capFlags));

    uint8_t data8 = 0;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_CAPABILITY_CT_EXPONENT,
                     &parameter, &data8, sizeof(data8));

    data8 = supportMeasurementSpec;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_MEASUREMENT_SPEC, &parameter,
                     &data8, sizeof(data8));
    uint32_t data32 = supportAsymAlgo;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_BASE_ASYM_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = supportHashAlgo;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_BASE_HASH_ALGO, &parameter,
                     &data32, sizeof(data32));
    data32 = supportMeasurementHashAlgo;
    libspdm_set_data(spdmContext, LIBSPDM_DATA_MEASUREMENT_HASH_ALGO,
                     &parameter, &data32, sizeof(data32));

    return true;
}

void SpdmMctpTransport::cleanupContext()
{
    if (scratchBuffer)
    {
        free(scratchBuffer);
        scratchBuffer = nullptr;
    }
    if (spdmContext)
    {
        libspdm_deinit_context(spdmContext);
        spdmContext = nullptr;
    }
}

libspdm_return_t SpdmMctpTransport::device_send_message(
    void* spdm_context, size_t message_size, const void* message,
    uint64_t timeout)
{
    try
    {
        libspdm_context_t* context =
            static_cast<libspdm_context_t*>(spdm_context);
        auto transport =
            static_cast<SpdmMctpTransport*>(context->app_context_data_ptr);
        if (!transport)
        {
            lg2::error("SpdmMctpTransport instance is nullptr");
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        std::vector<uint8_t> msg(
            static_cast<const uint8_t*>(message),
            static_cast<const uint8_t*>(message) + message_size);
        timeout_us_t timeoutUs = static_cast<timeout_us_t>(timeout);
        std::vector<uint8_t> mctpMessage;
        if (transport->mctpMessageTransport.encode(
                transport->eid, mctpMessage, msg) != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to encode MCTP message");
            return LIBSPDM_STATUS_SEND_FAIL;
        }
        libspdm_return_t ret = transport->mctpIo.write(mctpMessage, timeoutUs);
        if (ret != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to send SPDM message");
            return LIBSPDM_STATUS_SEND_FAIL;
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    catch (const std::exception&)
    {
        return LIBSPDM_STATUS_SEND_FAIL;
    }
}

libspdm_return_t SpdmMctpTransport::device_receive_message(
    void* spdm_context, size_t* message_size, void** message, uint64_t timeout)
{
    try
    {
        libspdm_context_t* context =
            static_cast<libspdm_context_t*>(spdm_context);
        auto transport =
            static_cast<SpdmMctpTransport*>(context->app_context_data_ptr);
        if (!transport)
        {
            return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
        }
        timeout_us_t timeoutUs = static_cast<timeout_us_t>(timeout);
        std::vector<uint8_t> response;
        libspdm_return_t ret = transport->mctpIo.read(response, timeoutUs);
        if (ret != LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to receive SPDM message");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        if (transport->mctpMessageTransport.decode(transport->eid, response,
                                                   message, message_size) !=
            LIBSPDM_STATUS_SUCCESS)
        {
            lg2::error("Failed to decode MCTP message");
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
        return LIBSPDM_STATUS_SUCCESS;
    }
    catch (const std::exception&)
    {
        return LIBSPDM_STATUS_RECEIVE_FAIL;
    }
}

libspdm_return_t SpdmMctpTransport::spdm_device_acquire_sender_buffer(
    void* context, void** msg_buf_ptr)
{
    libspdm_context_t* spdm_context = static_cast<libspdm_context_t*>(context);
    SpdmMctpTransport* transport =
        static_cast<SpdmMctpTransport*>(spdm_context->app_context_data_ptr);

    if (transport->sendReceiveBufferAcquired)
    {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }
    *msg_buf_ptr = transport->sendReceiveBuffer;
    libspdm_zero_mem(transport->sendReceiveBuffer,
                     sizeof(transport->sendReceiveBuffer));
    transport->sendReceiveBufferAcquired = true;

    return LIBSPDM_STATUS_SUCCESS;
}

void SpdmMctpTransport::spdm_device_release_sender_buffer(
    void* context, const void* /*msg_buf_ptr*/)
{
    libspdm_context_t* spdm_context = static_cast<libspdm_context_t*>(context);
    SpdmMctpTransport* transport =
        static_cast<SpdmMctpTransport*>(spdm_context->app_context_data_ptr);
    transport->sendReceiveBufferAcquired = false;
}

libspdm_return_t SpdmMctpTransport::spdm_device_acquire_receiver_buffer(
    void* context, void** msg_buf_ptr)
{
    libspdm_context_t* spdm_context = static_cast<libspdm_context_t*>(context);
    SpdmMctpTransport* transport =
        static_cast<SpdmMctpTransport*>(spdm_context->app_context_data_ptr);

    if (transport->sendReceiveBufferAcquired)
    {
        return LIBSPDM_STATUS_INVALID_STATE_LOCAL;
    }

    *msg_buf_ptr = transport->sendReceiveBuffer;
    libspdm_zero_mem(transport->sendReceiveBuffer,
                     sizeof(transport->sendReceiveBuffer));
    transport->sendReceiveBufferAcquired = true;

    return LIBSPDM_STATUS_SUCCESS;
}

void SpdmMctpTransport::spdm_device_release_receiver_buffer(
    void* context, const void* /*msg_buf_ptr*/)
{
    libspdm_context_t* spdm_context = static_cast<libspdm_context_t*>(context);
    SpdmMctpTransport* transport =
        static_cast<SpdmMctpTransport*>(spdm_context->app_context_data_ptr);
    transport->sendReceiveBufferAcquired = false;
}

} // namespace spdm

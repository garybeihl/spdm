// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: Copyright OpenBMC Authors

#include "mctp_transport_discovery.hpp"

#include "utils/mapper.hpp"

#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/UUID/client.hpp>
#include <xyz/openbmc_project/MCTP/Endpoint/client.hpp>

#include <ranges>

namespace spdm
{
PHOSPHOR_LOG2_USING;
using MctpEndpoint = sdbusplus::client::xyz::openbmc_project::mctp::Endpoint<>;
using CommonUUID = sdbusplus::client::xyz::openbmc_project::common::UUID<>;

auto MCTPTransportDiscovery::discovery(SPDMDiscovery& discovery)
    -> sdbusplus::async::task<>
{
    // The mapper raises ResourceNotFound when no MCTP endpoints exist.
    // On a freshly-booted system without any configured endpoints this would
    // otherwise propagate out of the discovery coroutine, terminate spdmd
    // before it claims its bus name, and trip the systemd start timeout.
    mapper::instances::instances_t instances;
    try
    {
        instances = co_await mapper::instances::by_interface<MctpEndpoint>(ctx);
    }
    catch (const std::exception& e)
    {
        debug("MCTP discovery: no endpoints found ({ERROR})", "ERROR",
              e.what());
        co_return;
    }

    for (const auto& [path, service] : instances)
    {
        try
        {
            auto endpointProps = co_await MctpEndpoint(ctx)
                                     .service(service)
                                     .path(path.str)
                                     .properties();

            if (!std::ranges::contains(endpointProps.supported_message_types,
                                       spdm_message_type))
            {
                debug("Endpoint {PATH} does not support SPDM", "PATH", path);
                continue;
            }

            auto uuidProps = co_await CommonUUID(ctx)
                                 .service(service)
                                 .path(path.str)
                                 .properties();

            debug("Found SPDM MCTP device at {PATH}, EID={EID}", "PATH", path,
                  "EID", endpointProps.eid);

            discovery.add(ResponderInfo{
                path, MctpResponderInfo{endpointProps.eid, uuidProps.uuid},
                TransportType::MCTP});
        }
        catch (const std::exception& e)
        {
            warning("MCTP discovery: failed to query endpoint {PATH}: {ERROR}",
                    "PATH", path, "ERROR", e.what());
        }
    }

    debug("MCTP transport discovery completed");
}

} // namespace spdm

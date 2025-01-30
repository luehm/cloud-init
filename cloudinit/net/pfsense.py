# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import logging
import re
import ipaddress

from cloudinit import util
import cloudinit.net.bsd
from cloudinit.distros import pfsense_utils as pf_utils

LOG = logging.getLogger(__name__)

class Renderer(cloudinit.net.bsd.BSDRenderer):

    static_routes_node = "./staticroutes"
    gateways_node = "./gateways"
    interfaces_node = "./interfaces"

    def __init__(self, config=None):
        super(Renderer, self).__init__()

    def _string_escape(self, string):
        return re.sub('[^a-zA-Z0-9_]+', '_', string).capitalize()

    def rename_interface(self, cur_name, device_name):
        raise NotImplementedError()
    
    def dhcp_interfaces(self):
        raise NotImplementedError()
    
    def start_services(self, run=False):
        pass
    
    def write_config(self):

        # Start from empty list of interfaces
        ifaces = {Renderer.interfaces_node.split('/')[-1]: []}

        devices = self.interface_configurations.keys() | self.interface_configurations_ipv6.keys()

        for device_name in devices:

            # Set basic interface properties
            # NOTE: <if> is the key value in the xml structure
            # MUST match the hardware interface name
            # The parent XML tag is set to this value for consistency
            iface = {device_name: {}}
            iface["if"] = device_name
            iface["descr"] = self._string_escape(device_name)
            iface["enable"] = ""

            # Check if we have ipv4 configuration for this interface
            if device_name in self.interface_configurations:
                v = self.interface_configurations[device_name]

                if isinstance(v, dict):
                    if v.get("address"):
                        iface["ipaddr"] = v.get("address")

                    if v.get("netmask"):
                        iface["subnet"] = v.get("netmask")

                    if v.get("mtu"):
                        iface["mtu"] = v.get("mtu")
                elif isinstance(v, str):
                    if v == "DHCP":
                        iface["ipaddr"] = "dhcp"

            # Check if we have ipv6 configuration for this interface
            if device_name in self.interface_configurations_ipv6:
                v = self.interface_configurations_ipv6[device_name]

                if isinstance(v, dict):

                    if v.get("address"):
                        iface["ipaddrv6"] = v.get("address")

                    if v.get("prefix"):
                        iface["subnetv6"] = v.get("prefix")

                    # ipv6 MTU takes precedence over ipv4
                    # - relaistically, only should be on one or the other
                    # - but if both, we'll use the ipv6 mtu
                    if v.get("mtu"):
                        iface["mtu"] = v.get("mtu")

                elif isinstance(v, str):
                    if v == "DHCP":
                        iface["ipaddrv6"] = "dhcp6"
            ifaces["interfaces"].append(iface)
        # Add the interface to the config
        pf_utils.append_config_element(Renderer.interfaces_node.split('/')[-2], ifaces)

        def _create_gateway(self, gateway):

            # Check if gateway already exists
            gateways = pf_utils.get_config_element(Renderer.gateways_node)
            for g in gateways:
                if g["gateway"] == gateway:
                    return g["name"]

            # Find interface for gateway
            c_ifaces = pf_utils.get_config_element(Renderer.interfaces_node)
            gw_iface_name = None
            ipprotocol = None
            for c_iface in c_ifaces:
                iface_ip = None
                if c_iface.get("ipaddr"):
                    iface_ip = c_iface.get("ipaddr")
                    ipprotocol = "inet"
                elif c_iface.get("ipaddrv6"):
                    iface_ip = c_iface.get("ipaddrv6")
                    ipprotocol = "inet6"

                if ipaddress.ip_address(gateway) in ipaddress.ip_network(iface_ip):
                    gw_iface_name = c_iface["if"]
                    break
                else:
                    continue
            if gw_iface_name is None:
                LOG.warning("No interface found for gateway %s", gateway)
                return False
                
            # Create new gateway
            gateway = {
                "gateway_item": {
                    "name": "GW_" + self._string_escape(gateway),
                    "gateway": gateway,
                    "interface": gw_iface_name,
                    "weight": 1,
                    "ipprotocol": ipprotocol,
                    "descr": f"Gateway for {gateway} on {gw_iface_name}",
                }
            }

            pf_utils.append_config_element("./gateways", gateway)
            return gateway["name"]

        def set_route(self, network, netmask, gateway):

            # Check if route exists
            routes = pf_utils.get_config_element(Renderer.static_routes_node)
            for r in routes:
                if r["network"] == f"{network}/{netmask}":
                    return

            gw_name = self._create_gateway(gateway)
            if not gw_name:
                LOG.warning("Failed to create static route %s via %s", f"{network}/{netmask}", gateway)
                return
            
            # Create new route
            route = {
                "route": {
                    "network": f"{network}/{netmask}",
                    "gateway": gw_name,
                    "descr": f"Route to {network}/{netmask} via {gateway}",
                }
            }

            # Write the route to the config
            pf_utils.append_config_element(Renderer.static_routes_node, route)

def available(target=None):
    return util.is_PFSense()
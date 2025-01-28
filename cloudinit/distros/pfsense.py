# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import logging
import os
import re
import xml.etree.ElementTree as ET
from io import StringIO

import cloudinit.distros.bsd
from cloudinit import subp, util
from cloudinit.distros.networking import FreeBSDNetworking
from cloudinit.settings import PER_INSTANCE

LOG = logging.getLogger(__name__)


class Distro(cloudinit.distros.freebsd.Distro):
    """
    Distro subclass for pfSense
    """

    pf_config_path = "/cf/conf/config.xml"

    group_add_cmd_prefix = None # groups are maintained within config.xml

    @classmethod
    def set_config_object(self, key, value, node=None):
        """
        For the given xml path, create an element with the specified properties.
        """

        # Find parent element in document
        tree = ET.parse(self.pf_config_path)
        root = tree.getroot()
        node = root.find(key)
        if node is None:
            raise ValueError("No such key: %s" % key)

        # Create new element 
        element = ET.Element(key)

        # Create element attributes, if provided
        for k, v in value.items():
            element.set(k, v)

        # Append element to parent node
        node.append(element)

        # Write changes to file
        tree.write(self.pf_config_path)

    @classmethod
    def set_config_value(self, key, value):
        """
        For the givem xml path, set the value of the specified element
        """

        # Find parent element in document
        tree = ET.parse(self.pf_config_path)
        root = tree.getroot()
        node = root.find(key)
        if node is None:
            raise ValueError("No such key: %s" % key)

        # Set element value
        node.text = value

        # Write changes to file
        tree.write(self.pf_config_path)

    @classmethod
    def get_config_object(self, key):
        """
        For the given xml path in key, get the element
        """

        # Find element in document
        tree = ET.parse(self.pf_config_path)
        root = tree.getroot()
        node = root.find(key)
        if node is None:
            raise ValueError("No such key: %s" % key)

        return node

    @classmethod
    def get_config_value(self, key):
        """
        For the given xml path in key, get the value
        """

        # Find element in document
        tree = ET.parse(self.pf_config_path)
        root = tree.getroot()
        node = root.find(key)
        if node is None:
            raise ValueError("No such key: %s" % key)

        return node.text

    @classmethod
    def reload_pf(cls, rcs=None):
        """
        Tell pf to reload its configuration
        """
        return subp.subp(["/etc/rc.reload_all"], capture=True, rcs=rcs)

    def create_group(self, name, members=None):
        raise NotImplementedError()

    def add_user(self, name, **kwargs):
        """
        Add a user to the system
        Users are stored within the pfsense/system element as a new user entry
        """

        user_parent_node = "pfsense/system"
        
        # Check if user already exists
        if util.is_user(name):
            LOG.info("User %s already exists, skipping.", name)
            return False

        # Create new user element
        user = ET.Element("user")

        # Set user attributes
        user.set("name", name)
        for key, val in kwargs.items():
            user.set(key, val)

        # Add user to system element
        self.set_config_object("system", user)

        # Reload pf
        self.reload_pf()

        return True
    
    def expire_passwd(self, user):
        raise NotImplementedError()
    
    def set_passwd(self, user, passwd):
        raise NotImplementedError()
    
    def chpasswd(self, user, passwd):
        raise NotImplementedError()
    
    def lock_passwd(self, user):
        raise NotImplementedError()
    
    def setup_user_keys(self, user, keys):
        raise NotImplementedError()
    
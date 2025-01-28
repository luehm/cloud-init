# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import bcrypt
import logging

import cloudinit.net.bsd
from cloudinit import distros, net, subp, util
from cloudinit.distros import pfsense_utils as pf_utils

LOG = logging.getLogger(__name__)


class Renderer(cloudinit.net.bsd.BSDRenderer):
    def create_group(self, name, gid=None):
        raise NotImplementedError()

    def add_user_to_group(self, user, group):

        next_gid_node = "./system/nextgid"
        raise NotImplementedError()

    def set_passwd(self, user, passwd, hashed=False):
        """
        Set the password for a user
        """

        # Check if user exists
        user_node = "./system/user"
        users = pf_utils.get_config_element(user_node)
        n = None
        for u in users:
            if u["name"] == user:
                n = u
                break
        if n is None:
            #LOG.error("User %s does not exist", user)
            return False

        # Set password
        if hashed:
            # Check if password is bcrypt format
            if passwd.startswith("$2a$"):
                n["bcrypt-hash"] = passwd
                pf_utils.set_config_value(user_node + "/bcrypt-hash", passwd)
            else:
                print("Invalid bcrypt hash: %s", passwd)
                #LOG.error("Invalid bcrypt hash: %s", passwd)
        else:
            # Generate bcrypt hash of user password
            n["bcrypt-hash"] = bcrypt.hashpw(passwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        pf_utils.replace_config_element(user_node, "name", user, n)

        return True

    def lock_passwd(self, user):
        raise NotImplementedError()

    def chpasswd(self, user, passwd):
        raise NotImplementedError()

    def add_user(self, name, **kwargs):
        """
        Add a user to the system
        Users are stored within the pfsense/system element as a new user entry

        Supported user properties:
        - gecos: User description
        - lock_passwd: Lock user password
        - expiredate: User expiration date
        - groups: List of groups to add user to
        - name: User name

        Supported in other modules:
        - groups
        - ssh_authorized_keys
        - plain_text_passwd
        - hashed_passwd
        - passwd
        """

        user_node = "./system/user"
        next_uid_node = "./system/nextuid"

        # Check if user already exists
        users = pf_utils.get_config_element(user_node)
        if [u for u in users if u["name"] == name]:
            #LOG.info("User %s already exists, skipping.", name)
            return False

        uid = pf_utils.get_config_value(next_uid_node)

        if name == None or name == "":
            #LOG.error("User name cannot be empty")
            return False

        # Create new user
        user = {}
        user["name"] = name
        user["uid"] = uid

        pf_utils.set_config_value(next_uid_node, str(int(uid) + 1))

        supported_user_passwd_formats = {
            "plain_text_passwd": False,
            "hashed_passwd": True,
            "passwd": True
        }

        for key, val in kwargs.items():
            if key == "gecos":
                user["descr"] = val
            elif key == "lock_passwd":
                user["disabled"] = None
            elif key == "expiredate":
                user["expires"] = val
            elif key == "groups":
                for group in val:
                    self.add_user_to_group(name, group)
            elif key == "ssh_authorized_keys":
                for key in val:
                    self.add_ssh_key(name, key)
            elif not [k for k in supported_user_passwd_formats.keys() if k == key]:
                #LOG.warning("Unsupported user property: %s", key)
                print(f"Unsupported user property: {key}")

        # Add user to system element
        pf_utils.append_config_element(user_node, user)

        for key, val in kwargs.items():
            if [k for k in supported_user_passwd_formats.keys() if k == key]:
                self.set_passwd(name, val, supported_user_passwd_formats[key])

        return True
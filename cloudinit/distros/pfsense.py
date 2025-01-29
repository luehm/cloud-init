# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import bcrypt
import logging

import cloudinit.distros.freebsd
from cloudinit import subp, util
import cloudinit.distros.pfsense_utils as pf_utils

#from cloudinit.distros.networking import FreeBSDNetworking
from cloudinit.settings import PER_INSTANCE

LOG = logging.getLogger(__name__)


class Distro(cloudinit.distros.freebsd.Distro):
    """
    Distro subclass for pfSense
    """

    user_node = "./system/user"
    group_node = "./system/group"
    next_uid_node = "./system/nextuid"
    next_gid_node = "./system/nextgid"

    def _reload_pf(self, cls, rcs=None):
        """
        Tell pf to reload its configuration
        """
        return subp.subp(["/etc/rc.reload_all"], capture=True, rcs=rcs)

    def create_group(self, name, members=None):
        """
        Create a new group
        Groups are stored within the pfsense/system element as a new group entry
        """

        # Check if group already exists
        groups = pf_utils.get_config_element(Distro.group_node)
        if [g for g in groups if g["name"] == name]:
            LOG.info("Group %s already exists, skipping.", name)
            return False

        # Check if name is empty
        if name == None or name == "":
            LOG.info("Unable to create group, name cannot be empty")
            return False

        # Get next available gid
        gid = pf_utils.get_config_value(Distro.next_gid_node)

        # Create new group
        group = {}
        group["name"] = name
        group["gid"] = gid
        group["scope"] = "system"

        # Increment next gid tracker
        pf_utils.set_config_value(Distro.next_gid_node, str(int(gid) + 1))

        if not members:
            members = []
        elif not isinstance(members, list):
            members = [members]

        # Add group members which currently exist on system
        group["gid"] = []
        existing_users = pf_utils.get_config_element(Distro.user_node)
        for member in members:
            if not [u for u in existing_users if u["name"] == member]:
                LOG.warning("Unable to add group member '%s' to group '%s'; user does not exist.", member, name)
                continue

            group["gid"].append(member["uid"])

        # Add group to system element
        pf_utils.append_config_element(Distro.group_node, group)

    def _add_user_to_group(self, user_id, group_name):
        """
        Add a user to a group
        """

        # Check if group exists
        groups = pf_utils.get_config_element(Distro.group_node)
        group = None
        for g in groups:
            if g["name"] == group_name:
                group = g
                break

        # If group does not exist, return
        if group is None:
            return False
        
        # If user is already in group, return
        if user_id in group["member"]:
            LOG.info("User %s already in group %s", user_id, group_name)
            return True

        # Add user to group
        group["member"].append(user_id)
        pf_utils.replace_config_element(Distro.group_node, "name", group_name, group)
        return True

        
    def _add_ssh_key(self, user, key):
        raise NotImplementedError()

    def set_passwd(self, user, passwd, hashed=False):
        """
        Set the password for a user
        """

        # Check if user exists
        users = pf_utils.get_config_element(Distro.user_node)
        n = None
        for u in users:
            if u["name"] == user:
                n = u
                break
        if n is None:
            LOG.info("User %s does not exist", user)
            return False

        # Set password
        if hashed:
            # Check if password is bcrypt format
            if passwd.startswith("$2a$"):
                n["bcrypt-hash"] = passwd
                pf_utils.set_config_value(Distro.user_node + "/bcrypt-hash", passwd)
            else:
                print("Invalid bcrypt hash: %s", passwd)
                LOG.info("Invalid bcrypt hash for user %s, skipping", user)
                return False
        else:
            # Generate bcrypt hash of user password
            n["bcrypt-hash"] = bcrypt.hashpw(passwd.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

            pf_utils.replace_config_element(Distro.user_node, "name", user, n)

        return True

    def lock_passwd(self, user):
        """
        Lock a user's password, effectively disabling the account.
        Implemented on pfSense by the <disabled> element in the user's configuration
        """

        # Check if user exists
        users = pf_utils.get_config_element(Distro.user_node)
        n = None
        for u in users:
            if u["name"] == user:
                n = u
                break
        if n is None:
            LOG.info("User %s does not exist", user)
            return False
        
        # Lock user password
        n["disabled"] = None
        pf_utils.replace_config_element(Distro.user_node, "name", user, n)
        return True

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
        - groups[list]: List of groups to add user to
        - ssh_authorized_keys
        - plain_text_passwd
        - hashed_passwd
        - passwd

        """

        # Check if user already exists
        users = pf_utils.get_config_element(Distro.user_node)
        if [u for u in users if u["name"] == name]:
            LOG.info("User %s already exists, skipping.", name)
            return False

        if name == None or name == "":
            LOG.info("Unable to create user, name cannot be empty")
            return False
        
        uid = pf_utils.get_config_value(Distro.next_uid_node)

        # Create new user
        user = {}
        user["name"] = name
        user["uid"] = uid

        # Increment next uid tracker
        pf_utils.set_config_value(Distro.next_uid_node, str(int(uid) + 1))

        supported_user_passwd_formats = {
            "plain_text_passwd": False,
            "hashed_passwd": True,
            "passwd": True
        }

        for key, val in kwargs.items():
            if key == "gecos":
                user["descr"] = val
            elif key == "expiredate":
                user["expires"] = val
            elif key == "ssh_authorized_keys":
                for key in val:
                    self._add_ssh_key(name, key)

        # Add user to system element
        pf_utils.append_config_element(Distro.user_node, user)

        # Parse remaining user properties
        for key, val in kwargs.items():
            if [k for k in supported_user_passwd_formats.keys() if k == key]:
                self.set_passwd(name, val, supported_user_passwd_formats[key])
            elif key == "groups":
                if not isinstance(val, list):
                    val = [val]
                for group in val:
                    if not self._add_user_to_group(uid, group):
                        LOG.warning("Unable to add user '%s' to group '%s - group does not exist'", name, group)

            elif key == "expired":
                self.lock_passwd(name)

        return True
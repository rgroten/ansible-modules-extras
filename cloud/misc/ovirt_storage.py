#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2016, Ryan Groten <rgroten@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: ovirt_storage
author: "Ryan Groten (@rgroten)"
short_description: "Create/Delete/Manage VM Disks in oVirt/RHEV"
description:
    - Module for managing disks in oVirt/RHEV. Provides the ability to create, attach/detach, or delete both internal (pool) disks to VMs.
version_added: "2.2"
requirements:
    - "ovirt-engine-python-sdk"
options:
    state:
        description:
            - C(present) will create a new disk and attach it to a VM.
            - C(absent) will delete a disk attached to a VM.
            - C(attach) will attach a disk to a VM.
            - C(detach) will detach a disk from a VM.
        choices: [ 'present', 'absent', 'attached', 'detached' ]
        default: present
    user:
        description:
            - User with access to perform disk operations in oVirt.
        required: true
    password:
        description:
            - Password for I(user).
        required: true
    url:
        description:
            - URL to oVirt API (U(https://<ovirt-engine>/api)).
        required: true
    vm_name:
        description:
            - Name of the VM in oVirt.
        required: true
    disk_alias:
        description:
            - Alias of the oVirt disk to perform operation on.
        required: true
    disk_size_gb:
        description:
            - Size in GB of new disk image. Used when C(state) is C(present).
    disk_lunid:
        description:
            - Create a direct attach fibre channel lun. Must match lunid as the oVirt host sees it. Used when C(state) is C(present).
    disk_iface:
        description:
            - Interface for newly created disk. Used when C(state) is C(present).
        default: virtio
        choices: [ 'virtio', 'ide' ]
    disk_alloc:
        description:
            - Allocation Policy for newly created disk. Used when C(state) is C(present).
        default: cow
        choices: [ 'cow', 'raw' ]
    disk_activate:
        description:
            - If C(yes), disk will be activated when created or attached to a VM.
            - If C(no), disk will be attached but not activated. 
            - Used when C(state) is C(present) or C(attached).
        default: True
        type: bool
'''

EXAMPLES = '''
# Create a new 5GB Pool Disk and attach/activate it to a VM
- action: ovirt_storage:
    vm_name: vm.example.com
    disk_alias: disk1
    disk_size_gb: 5
    url: "https://ovirt-manager.example.com/api"
    user: admin@internal
    password: adminpw
# Attach an existing disk to a VM but don't activate it
- action: ovirt_storage:
    vm_name: vm.example.com
    disk_alias: disk1
    url: "https://ovirt-manager.example.com/api"
    user: admin@internal
    password: adminpw
    state: attached
    disk_activate: False
# Detach an existing disk from a VM (disk will not be deleted)
- action: ovirt_storage:
    vm_name: vm.example.com
    disk_alias: disk1
    url: "https://ovirt-manager.example.com/api"
    user: admin@internal
    password: adminpw
    state: detached
# Delete an existing disk from a VM (disk will be permanently removed)
- action: ovirt_storage:
    vm_name: vm.example.com
    disk_alias: disk1
    url: "https://ovirt-manager.example.com/api"
    user: admin@internal
    password: adminpw
    state: absent
# Attach a fibre channel lun to a VM
- action: ovirt_storage:
    vm_name: vm.example.com
    disk_alias: disk1
    url: "https://ovirt-manager.example.com/api"
    user: admin@internal
    password: adminpw
    disk_lunid: "3600..."
'''

from ovirtsdk.api import API
from ovirtsdk.xml import params

def _activate(disk):
    """
    Activate specified disk
    Parameters:
        disk - ovirtsdk.infrastructure.brokers.VMDisk object to activate
    Returns:
        0 - No change
        1 - Change
    """
    try:
        if disk.get_active():
            # Disk is already active 
            return 0
        else:
            if not MODULE_CHECK_MODE:
                disk.activate()
            return 1
    except Exception as e:
        raise Exception("Error while activating disk: " + str(e))


def _deactivate(disk):
    """
    Deactivate specified disk
    Parameters:
        disk - ovirtsdk.infrastructure.brokers.VMDisk object to deactivate
    Returns:
        0 - No change
        1 - Change
    """
    try:
        if disk.get_active():
            if not MODULE_CHECK_MODE:
                disk.deactivate()
            return 1
        else:
            return 0
    except Exception as e:
        raise Exception("Error while deactivating disk: " + str(e))


def _attach(vm, disk, activate):
    """
    Attach specified disk to VM
    Parameters:
        disk - ovirtsdk.infrastructure.brokers.Disk object to attach
        vm - ovirtsdk.infrastructure.brokers.VM object to attach disk to
    Returns:
        0 - No change
        1 - Change
    """
    vm_disk = vm.disks.get(id=disk.id)
    # Check if disk is already attached to the VM
    if vm_disk:
        # Disk is already attached so lets activate it
        if activate:
            return _activate(vm_disk)
    else:
        if not MODULE_CHECK_MODE:
            vm_disk = vm.disks.add(params.Disk(id = disk.id, active = activate))
        return 1
    return 0


def _detach(vm, disk):
    """
    Detach specified disk from VM
    Parameters:
        disk - ovirtsdk.infrastructure.brokers.VMDisk object to detach
        vm - ovirtsdk.infrastructure.brokers.VM object to detach disk from
    Returns:
        0 - No change
        1 - Change
    """
    if not MODULE_CHECK_MODE:
        disk.delete(action=params.Action(detach=True))
    return 1


def attach_disk(api, vm_name, disk_alias, activate=True):
    """
    Attach disk_alias to vm_name then activate it by default
    Parameters:
      vm_name - string of VM to attach disk to
      disk_alias - string of disk to attach to VM
    """
    try:
        vm = api.vms.get(name=vm_name)
        disks = api.disks.list(alias=disk_alias)
        ret = 0
        if not disks:
            raise Exception("No disks with name " + disk_alias + " found")
        for disk in disks.__iter__():
            ret += _attach(vm, disk, activate)
        return ret
    except Exception as e:
        raise Exception("Error while attaching disk")


def detach_disk(api, vm_name, disk_alias, detach=True):
    """
    Deactivate disk_alias and by default detach it from vm_name
    """
    try:
        vm = api.vms.get(name=vm_name)
        disks = vm.disks.list(alias=disk_alias)
        ret = 0
        if not disks:
            raise Exception("No disks with name " + disk_alias + " are attached to " + vm_name)
        for disk in disks.__iter__():
            ret += _deactivate(disk)
            if detach:
                ret += _detach(vm, disk)
        return ret
    except Exception as e:
        raise Exception("Exception while detaching disk " + str(e))


def create_disk(api, vm_name, disk_alias, disk_size_gb, disk_alloc, disk_iface):
    """Create a new disk with specified name and size. Attach to vm_name"""
    try:
        vm = api.vms.get(name=vm_name)
        disks = vm.disks.list(alias=disk_alias)
        if disks:
            return 0
        if not MODULE_CHECK_MODE:
            size = int(disk_size_gb) * 1024 * 1024 * 1024
            disk_params = params.Disk()
            disk_params.set_wipe_after_delete(True)
            #disk_params.set_sparse(False)
            disk_params.set_active(True)
            disk_params.set_alias(disk_alias)
            disk_params.set_size(size)
            disk_params.set_interface(disk_iface)
            disk_params.set_format(disk_alloc)
            disk = vm.disks.add(disk_params)
            # TODO: Use VMDisk.get_creation_status to wait until disk creation completes
        return 1
    except Exception as e:
        raise Exception("Error while creating new disk: " + str(e))


def create_lun(api, vm_name, disk_alias, lun_id):
    """
    Create a new direct attach disk from lun_id then attach to vm_name
    """
    try:
        lu = params.LogicalUnit()
        lu.set_id(lun_id)

        lus = list()
        lus.append(lu)

        storage_params = params.Storage()
        storage_params.set_id(lun_id)
        storage_params.set_logical_unit(lus)
        storage_params.set_type('fcp')
        disk_params = params.Disk()
        disk_params.set_format('raw')
        disk_params.set_interface('virtio')
        disk_params.set_alias(disk_alias)
        disk_params.set_active(True)
        disk_params.set_lun_storage(storage_params)

        if vm_name:
            if not MODULE_CHECK_MODE:
                vm = api.vms.get(name=vm_name)
                disk = vm.disks.add(disk_params)
        else:
            if not MODULE_CHECK_MODE:
                disk = api.disks.add(disk_params)
        return 1
    except Exception as e:
        raise Exception("Error while adding new lun: " + str(e))


def delete_disk(api, disk_alias, vm_name=None, assume_yes=True):
    """
    Permanently delete disk_alias from RHEV. Expects disk to be detached 
    already. Unless -y is specified in command line, prompt user to confirm
    before deleting.
    """
    ret = 0
    if vm_name:
        ret += detach_disk(api, vm_name, disk_alias)

    try:
        disks = api.disks.list(alias=disk_alias)
        if not disks:
            raise Exception("No disks with name " + disk_alias + " are attached to " + vm_name)
        for disk in disks.__iter__():
            if disk is None:
                raise Exception("No such disk")

            if not MODULE_CHECK_MODE:
                disk.delete()
            ret += 1
        return ret
    except Exception as e:
        raise Exception("Error while deleting disk: " + str(e))


def ovirtConnect(url, username, password):
    """Connect to hostname oVirt server using user/password"""
    api = API(url=url, username=username, password=password, insecure=True)
    return api


def main():
    """Main Function"""

    module = AnsibleModule(
        argument_spec = dict(
            state = dict(default='present', choices=['present', 'absent', 'attached', 'detached']),
            user = dict(required=True),
            url = dict(required=True),
            vm_name = dict(required=True),
            password = dict(required=True, no_log=True),
            disk_size_gb = dict(),
            disk_alias = dict(required=True),
            disk_iface = dict(default='virtio', choices=['virtio', 'ide']),
            disk_alloc = dict(default='cow', choices=['cow', 'raw']),
            disk_activate = dict(type='bool', default=True, choices=[True, False]),
            disk_lunid = dict(aliases=['disk_wwid'])
        ),
        supports_check_mode = True
    ) 

    state         = module.params['state']
    ovirt_user    = module.params['user']
    ovirt_pw      = module.params['password']
    ovirt_url     = module.params['url']
    vm_name       = module.params['vm_name']
    disk_size_gb  = module.params['disk_size_gb']
    disk_alias    = module.params['disk_alias']
    disk_iface    = module.params['disk_iface']
    disk_alloc    = module.params['disk_alloc']
    disk_act      = module.params['disk_activate']
    disk_deact    = module.params['disk_activate']
    disk_lunid    = module.params['disk_lunid']
    global MODULE_CHECK_MODE
    MODULE_CHECK_MODE = module.check_mode
    ret = 0

    try:
        api = ovirtConnect(ovirt_url, ovirt_user, ovirt_pw)
    except Exception, e:
        module.fail_json(msg='%s' %e)

    try:
        if state == 'attached':
            ret = attach_disk(api, vm_name, disk_alias, disk_act)
            if ret > 0:
                msg = "Attached %s disk to %s" % (disk_alias, vm_name)
            else:
                msg = "Disk %s is already attached to %s" % (disk_alias, vm_name)
        elif state == 'detached':
            ret = detach_disk(api, vm_name, disk_alias, disk_deact)
            if ret > 0:
                msg = "Detached %s disk from %s" % (disk_alias, vm_name)
            else:
                msg = "No disk named %s attached to %s" % (disk_alias, vm_name)
        elif state == 'present':
            if disk_lunid:
                ret = create_lun(api, vm_name, disk_alias, disk_lunid)
            else:
                if not disk_size_gb:
                    raise Exception("disk_size_gb is required to create an image")
                ret = create_disk(api, vm_name, disk_alias, disk_size_gb, disk_alloc, disk_iface)
            if ret > 0:
                msg = "Created new disk %s and activated on %s" % (disk_alias, vm_name)
            else:
                msg = "Disk %s already exists" % disk_alias
        elif state == 'absent':
            ret = delete_disk(api, disk_alias, vm_name)
            msg = "Deleted disk %s from %s" % (disk_alias, vm_name)
        else:
            raise Exception("Unsupported operation %s" % state)
    except Exception, e:
        module.fail_json(msg='%s' %e)
    finally:
        if api:
            api.disconnect()
    if ret > 0:
        module.exit_json(changed=True, msg=msg + " Num changes: " + str(ret))
    else:
        module.exit_json(changed=False, msg=msg)

from ansible.module_utils.basic import AnsibleModule
MODULE_CHECK_MODE = False
if __name__ == '__main__':
    main()

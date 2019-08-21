#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2019 VMware, Inc.
# SPDX-License-Identifier: GPL-3.0-or-later
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
# todos:
#     - 'delete diskgroups'
#     - 'add disks to existing diskgroups, when no unused cachedisk is available'

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: vmware-vsan-diskgroup
short_description: adds diskgroups to vSAN Cluster
description: adds all vSAN-eligible disks of an ESXi host to the vSAN cluster

version_added: "2.7"
author:
  - Christian Neugum (@digifuchsi)
options:
    hostname:
        description: The hostname or IP address of vCenter
        required: true
        type: str
    username:
        description: The username to authenticate with the vCenter.
        required: true
        type: str
    password:
        description: The password to authenticate with the vCenter.
        required: true
        type: str
    port:
        description: The port to use to connect to the vCenter.
        required: false
        type: int
        default: 443
    validate_certs:
        description: Validate the vCenter certificate.
        required: false
        type: bool
        default: true
    datacenter_name:
        description: The name of the datacenter the cluster belongs to
        required: true
        type: str
    cluster_name:
        description: The name of the cluster the ESXi host belongs to
        required: true
        type: str
    esxi_hostname:
        description: The hostname of the ESXi host to manipulate diskgroups for
        required: true
        type: str
    allFlash:
        description: Set to true if using all flash vSAN (ignores HDDs)
        required: false
        type: bool
        default: false
    state:
        description: Set to present to add diskgroups, absent to delete them
        required: false
        type: str
        choices: ['present', 'absent']
        default: 'present'
'''

EXAMPLES = '''
- name: adds diskgroups to a hybrid vSAN cluster
  vmware-vsan-diskgroup:
      hostname: "{{ vCenter_hostname }}"
      username: "{{ vCenter_username }}"
      password: "{{ vCenter_password }}"
      validate_certs: False
      datacenter_name: "{{ ESXi_host.datacenter_name }}"
      cluster_name: "{{ ESXi_host.cluster_name }}"
      esxi_hostname: "{{ ESXi_host.name }}"

- name: adds diskgroups to a all-flash vSAN cluster
  vmware-vsan-diskgroup:
      hostname: "{{ vCenter_hostname }}"
      username: "{{ vCenter_username }}"
      password: "{{ vCenter_password }}"
      validate_certs: False
      datacenter_name: "{{ ESXi_host.datacenter_name }}"
      cluster_name: "{{ ESXi_host.cluster_name }}"
      esxi_hostname: "{{ ESXi_host.name }}"
      allFlash: true

- name: removes all diskgroups from a vSAN cluster
  vmware-vsan-diskgroup:
      hostname: "{{ vCenter_hostname }}"
      username: "{{ vCenter_username }}"
      password: "{{ vCenter_password }}"
      validate_certs: False
      datacenter_name: "{{ ESXi_host.datacenter_name }}"
      cluster_name: "{{ ESXi_host.cluster_name }}"
      esxi_hostname: "{{ ESXi_host.name }}"
      state: 'absent'
'''

RETURN = '''
result:
    description: information about performed operation
    returned: on_changed
    type: str
    sample: "returns result of vSphere task"
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible.module_utils.vmware import vmware_argument_spec
import sys
import ssl
import atexit
import time
import traceback

PYVMOMI_IMP_ERR = None
try:
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
    from pyVim.task import WaitForTask
    import ansible.module_utils.vsanmgmtObjects
    import ansible.module_utils.vsanapiutils
    HAS_PYVMOMI = True
except ImportError:
    PYVMOMI_IMP_ERR = traceback.format_exc()
    HAS_PYVMOMI = False


class VmwareVsanDiskGroup(object):
    def __init__(self, module):
        # set SSL cert checking
        context = ssl.create_default_context()
        if not module.params['validate_certs']:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        else:
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED

        # connect to vCenter API
        self.si = SmartConnect(host=module.params['hostname'],
                               user=module.params['username'],
                               pwd=module.params['password'],
                               port=int(module.params['port']),
                               sslContext=context)
        atexit.register(Disconnect, self.si)

        self.content = self.si.RetrieveContent()
        self.module = module
        self.cluster = None
        self.datacenter = None
        self.host = None
        self.isAllFlash = module.params['allFlash']

        # pre-checks
        aboutInfo = self.si.content.about
        if aboutInfo.apiType != 'VirtualCenter':
            module.fail_json(msg="module requires connection to a vCenter Server, not ESXi host")

        majorApiVersion = aboutInfo.apiVersion.split('.')[0]
        if int(majorApiVersion) < 6:
            module.fail_json(msg="This vCenter Server has version %s (lower than 6.0) is not supported." % aboutInfo.apiVersion)

        # get vcMos
        vcMos = ansible.module_utils.vsanapiutils.GetVsanVcMos(self.si._stub, context=context)
        self.vsanDiskManagementSystem = vcMos['vsan-disk-management-system']

        # find datacenter, cluster and host
        datacenters = self.content.rootFolder.childEntity
        for dc in datacenters:
            if dc.name == module.params['datacenter_name']:
                self.datacenter = dc

                clusters = dc.hostFolder.childEntity
                for cl in clusters:
                    if cl.name == module.params['cluster_name']:
                        self.cluster = cl

                        hosts = cl.host
                        for ho in hosts:
                            if ho.summary.config.name == module.params['esxi_hostname']:
                                self.host = ho
                                break
                        break
                break

    def vsan_process_state(self):
        # object to choose operation
        if self.module.check_mode:
            vsan_states = {
                'absent': {
                    'absent': self.state_exit_unchanged,
                    'present': self.state_destroy_diskgroup,
                },
                'present': {
                    'absent': self.state_create_diskgroup,
                    'present': self.state_exit_unchanged,
                }
            }
        else:
            vsan_states = {
                'absent': {
                    'absent': self.state_exit_unchanged,
                    'present': self.state_exit_checkmode,
                },
                'present': {
                    'absent': self.state_exit_checkmode,
                    'present': self.state_exit_unchanged,
                }
            }

        # get current and desired state
        desired_state = self.module.params['state']
        current_state = self.current_state_vsan()
        # trigger function to to react to state
        vsan_states[desired_state][current_state]()

    def current_state_vsan(self):
        '''
        Gets current state
        :return:
        '''
        # set default state
        state = 'present'

        # check if all disks are mapped to vSAN diskgroups
        # if not set current state to absent
        if self.isAllFlash:
            ssds = [result.disk for result in self.host.configManager.vsanSystem.QueryDisksForVsan() if result.state == 'eligible' and result.disk.ssd]
            if len(ssds) > 0:
                state = 'absent'
        else:
            disks = [result.disk for result in self.host.configManager.vsanSystem.QueryDisksForVsan() if result.state == 'eligible']
            if len(disks) > 0:
                state = 'absent'

        return state

    def state_create_diskgroup(self):
        '''
        Creates disk group for list of specified hosts
        :return:
        '''
        cacheDisks = []
        capacityDisks = []

        # For all flash architectures
        if self.isAllFlash:
            ssds = [result.disk for result in self.host.configManager.vsanSystem.QueryDisksForVsan() if result.state == 'eligible' and result.disk.ssd]
            smallerSize = min([disk.capacity.block * disk.capacity.blockSize for disk in ssds])

            # make small SSDs cache tier
            for ssd in ssds:
                size = ssd.capacity.block * ssd.capacity.blockSize
                if size == smallerSize:
                    cacheDisks.append(ssd)
                else:
                    capacityDisks.append(ssd)
        # For hybrid architectures
        else:
            disks = [result.disk for result in self.host.configManager.vsanSystem.QueryDisksForVsan() if result.state == 'eligible']
            ssds = [disk for disk in disks if disk.ssd]
            hdds = [disk for disk in disks if not disk.ssd]
            for ssd in ssds:
                cacheDisks.append(ssd)
            for hdd in hdds:
                capacityDisks.append(hdd)

        # Build Disk Mapping Spec
        dm = vim.VimVsanHostDiskMappingCreationSpec(
            cacheDisks=cacheDisks,
            capacityDisks=capacityDisks,
            creationType='allFlash' if self.isAllFlash else 'hybrid',
            host=self.host)

        # Execute the task
        vsanTask = self.vsanDiskManagementSystem.InitializeDiskMappings(dm)
        changed, result = self.wait_for_vsanTask(vsanTask)

        self.module.exit_json(changed=changed, result=result, msg='CREATE')

    def state_destroy_diskgroup(self):
        '''
        Destroys diskgroups
        :return:
        '''
        # TODO

        self.module.fail_json(msg='NOT IMPLEMENTED')

    def state_exit_unchanged(self):
        '''
        No changes made
        :return:
        '''
        self.module.exit_json(changed=False, msg='EXIT UNCHANGED')

    def state_exit_checkmode(self):
        '''
        Checkmode skipping changes
        :return:
        '''
        self.module.exit_json(changed=True, msg='WOULD HAVE CHANGED')

    def wait_for_vsanTask(self, vsanTask):
        vcTask = ansible.module_utils.vsanapiutils.ConvertVsanTaskToVcTask(vsanTask, self.si._stub)
        state = WaitForTask(vcTask)

        if state == vim.TaskInfo.State.success:
            changed = True
            result = vcTask.info.state
        else:
            changed = False
            result = vcTask.info.error

        return changed, result


def main():
    argument_spec = vmware_argument_spec()
    argument_spec.update(dict(
        hostname=dict(type='str', required=True),
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        port=dict(type='int', required=False, default=443),
        validate_certs=dict(type='bool', required=False, default=True),
        datacenter_name=dict(type='str', required=True),
        cluster_name=dict(type='str', required=True),
        esxi_hostname=dict(type='str', required=True),
        allFlash=dict(type='bool', required=False, default=False),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent'])
    ))

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=False)

    if not HAS_PYVMOMI:
        module.fail_json(msg=missing_required_lib('PyVmomi'),
                         exception=PYVMOMI_IMP_ERR)

    vsan = VmwareVsanDiskGroup(module)
    vsan.vsan_process_state()


if __name__ == "__main__":
    main()

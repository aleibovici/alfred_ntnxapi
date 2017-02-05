#!/usr/bin/python
#
#  Andre Leibovici (andre@nutanix.com)
#
#  license: GNU LGPL
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public
#  License as published by the Free Software Foundation; either
#  version 2.1 of the License, or (at your option) any later version.

import argparse
import time
import datetime
import sys
import os
from workflow import Workflow, ICON_SWITCH, ICON_INFO, ICON_SETTINGS, ICON_NOTE, ICON_WARNING, \
    ICON_ERROR
from workflow.notify import notify
from plistlib import readPlist, writePlist


# GitHub repo for self-updating
UPDATE_SETTINGS = {
    # Username and the workflow's repo's name
    'github_slug': 'aleibovici/alfred_ntnxapi',
    # Number of days between checks for updates
    'frequency': 1
}


# Workflow icons
ICON_ON = 'icons/on.png'
ICON_OFF = 'icons/off.png'
ICON_NORMAL = 'icons/normal.png'
ICON_AHV = 'icons/ahv.png'
ICON_AHV_ON = 'icons/ahv_on.png'
ICON_AHV_AMBER = 'icons/ahv_amber.png'
ICON_AHV_ALERT = 'icons/ahv_alert.png'
ICON_CLONE = 'icons/clone.png'
ICON_SNAPSHOT = 'icons/snapshot.png'
ICON_MAINTENANCE = 'icons/maintenance.png'
ICON_BACK = 'icons/back.png'


# Default Nutanix API URI
API_VERSION = '1.0'
API_AHV = ':9440/api/nutanix/v0.8'
API_PRISM = ':9440/PrismGateway/services/rest/v1'
hypervisorType = ''
hypervisorState = ''
powerstate = ''
vmName = ''
hostUuid = ''
vmId = ''


# Filter ignore Keys
KEY_IGNORE_VM = {}
KEY_IGNORE_HOST = {}
KEY_IGNORE_CLUSTER = {}


def __install_and_import_package(package):
    import importlib
    try:
        importlib.import_module(package)
    except ImportError:
        import pip
        pip.main(['install', '--user', package])
    finally:
        globals()[package] = importlib.import_module(package)


def __define_api_version():
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    global API_VERSION
    global API_PRISM
    global API_AHV
    global hypervisorType
    global hypervisorState
    global powerstate
    global vmName
    global hostUuid
    global vmId
    global KEY_IGNORE_VM
    global KEY_IGNORE_HOST
    global KEY_IGNORE_CLUSTER

    API_AHV = ':9440/api/nutanix/v0.8'

    if ntnxapi_data['api'] == '1.0':
        API_VERSION = '1.0'
        API_PRISM = ':9440/PrismGateway/services/rest/v1'
        hypervisorType = 'hypervisorType'
        hypervisorState = 'hypervisorState'
        powerstate = 'powerState'
        vmName = 'vmName'
        hostUuid = 'hostUuid'
        vmId = 'vmId'
        KEY_IGNORE_VM = {'vmDisks', 'vmNics', 'containerIds', 'vmId', 'virtualNicIds', 'vdiskFilePaths', 'stats', 'uuid', 'nutanixVirtualDisks', 'nutanixVirtualDisksIds', 'nutanixVirtualDiskUuids',
                         'nutanixVirtualDiskIds', 'hostId', 'hostUuid', 'clusterUuid', 'usageStats', 'virtualNicUuids', 'containerUuids', 'nutanixGuestTools', 'runningOnNdfs', 'vdiskNames', 'displayable', 'guestOperatingSystem', 'acropolisVm', 'powerState', 'onDiskDedup', 'fingerPrintOnWrite', 'controllerVm', 'numNetworkAdapters', 'memoryReservedCapacityInBytes', 'cpuReservedInHz', 'diskCapacityInBytes'}
        KEY_IGNORE_HOST = {'dynamicRingChangingNode', 'keyManagementDeviceToCertificateStatus', 'stats', 'diskHardwareConfigs', 'usageStats', 'position', 'state', 'hostNicIds', 'hasCsr', 'vzoneName', 'bootTimeInUsecs', 'defaultVhdLocation', 'defaultVhdContainerId', 'removalStatus', 'defaultVmContainerUuid', 'defaultVhdContainerUuid', 'defaultVmLocation', 'clusterUuid',
                           'defaultVmContainerId', 'blockModel', 'serviceVmId', 'oplogDiskSize', 'metadataStoreStatusMessage', 'uuid', 'ipmiPassword', 'ipmiUsername', 'hypervisorUsername', 'serviceVMId', 'metadataStoreStatus', 'hypervisorPassword', 'blockLocation', 'hostMaintenanceModeReason', 'rebootPending', 'monitored', 'oplogDiskPct', 'failoverClusterNodeState', 'bmcModel', 'biosModel', 'cpuModel', 'failoveClusterFqdn', 'bmcVersion', 'biosVersion', 'cpuCapacityInHz', 'cpuFrequencyInHz', 'isDegraded', 'hbaFirmwaresList', 'memoryCapacityInBytes'}
        KEY_IGNORE_CLUSTER = {'stats', 'usageStats', 'cloudcluster', 'hypervisorSecurityComplianceConfig', 'securityComplianceConfig', 'rackableUnits', 'publicKeys', 'clusterRedundancyState', 'globalNfsWhiteList', 'multicluster', 'serviceCenters', 'clusterUuid', 'supportVerbositySite', 'id', 'clusterIncarnationId',
                              'credential', 'httpProxies', 'uuid', 'allHypervNodesInFailoverCluster', 'supportVerbosityType', 'fullVersion', 'enableLockDown', 'isUpgradeInProgress', 'nosClusterAndHostsDomainJoined', 'enablePasswordRemoteLoginToCluster', 'ssdPinningPercentageLimit', 'fingerprintContentCachePercentage', 'domain', 'enableShadowClones', 'disableDegradedNodeMonitoring', 'enforceRackableUnitAwarePlacement', 'iscsiConfig', 'smtpServer', 'managementServers', 'commonCriteriaMode', 'isSspEnabled', 'operationMode'}

    elif ntnxapi_data['api'] == '2.0':
        API_VERSION = '2.0'
        API_PRISM = ':9440/PrismGateway/services/rest/v2.0'
        hypervisorType = 'hypervisor_type'
        hypervisorState = 'hypervisor_state'
        powerstate = 'power_state'
        vmName = 'name'
        hostUuid = 'host_uuid'
        vmId = 'uuid'
        KEY_IGNORE_VM = {'host_uuid', 'power_state', 'uuid', 'vm_disk_info', 'is_cdrom', 'is_empty', 'is_flash_mode_enabled', 'is_scsi_passthrough', 'is_thin_provisioned', 'shared', 'source_disk_address', 'disk_address', 'vm_logical_timestamp', 'vm_nics', 'name'}
        KEY_IGNORE_HOST = {'service_vmid', 'uuid', 'disk_hardware_configs', 'hypervisor_username', 'hypervisor_password', 'ipmi_username', 'ipmi_password', 'monitored', 'position', 'block_location', 'metadata_store_status_message', 'dynamic_ring_changing_node', 'removal_status', 'vzone_name', 'cpu_frequency_in_hz', 'cpu_capacity_in_hz', 'boot_time_in_usecs', 'failover_cluster_fqdn', 'failover_cluster_node_state', 'reboot_pending', 'default_vm_location', 'default_vm_storage_container_id', 'default_vm_storage_container_uuid', 'default_vhd_location', 'default_vhd_storage_container_id', 'default_vhd_storage_container_uuid', 'cluster_uuid', 'stats', 'usage_stats', 'has_csr', 'host_nic_ids', 'key_management_device_to_certificate_status', 'host_in_maintenance_mode', 'metadata_store_status', 'host_maintenance_mode_reason', 'block_model', 'oplog_disk_size', 'bios_model', 'bios_version', 'bmc_model', 'bmc_version', 'state', 'oplog_disk_pct', 'hba_firmwares_list', 'hypervisor_state', 'is_degraded', 'memory_capacity_in_bytes', 'cpu_model', 'name'}
        KEY_IGNORE_CLUSTER = {'id', 'uuid', 'cluster_incarnation_id', 'cluster_uuid', 'support_verbosity_type', 'enable_password_remote_login_to_cluster', 'fingerprint_content_cache_percentage', 'global_nfs_white_list', 'security_compliance_config', 'hypervisor_security_compliance_config', 'iscsi_config', 'ssd_pinning_percentage_limit', 'stats', 'usage_stats', 'disable_degraded_node_monitoring', 'common_criteria_mode', 'full_version', 'credential', 'all_hyperv_nodes_in_failover_cluster', 'nos_cluster_and_hosts_domain_joined', 'has_self_encrypting_drive', 'cluster_redundancy_state', 'public_keys', 'http_proxies', 'rackable_units', 'enable_shadow_clones', 'management_servers', 'is_upgrade_in_progress', 'service_centers', 'enable_lock_down', 'operation_mode', 'cloudcluster', 'enforce_rackable_unit_aware_placement', 'name_servers', 'ntp_servers', 'smtp_server', 'multicluster', 'name'}


def __supress_security():
    # supress the security warnings
    requests.packages.urllib3.disable_warnings()


def __retrieve_config_data():
    # request saved config data
    return wf.stored_data('ntnxapi_data')


def __retrieve_env_variable(variable):
    return str(os.getenv(variable))


def __save_env_variable(variable, value):
    # retrieve info.plist
    info = readPlist('info.plist')
    # Set a variable
    info['variables'][variable] = str(value)
    # Save changes
    writePlist(info, 'info.plist')


def __reset_env_variable(variable):
    # retrieve info.plist
    info = readPlist('info.plist')
    # Set an empty variable
    info['variables'][variable] = str('')
    # Save changes
    writePlist(info, 'info.plist')


def __request_logicaltimestampdtop_vm(uuid):
    # request LogicalTimestampDTO for vm operations
    # this property is only available with API_AHV

    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_AHV + "/vms/" + uuid

    json_object = json.loads(__htpp_request(base_url))

    return str(json_object['logicalTimestamp'])


def __htpp_request(base_url):
    # supress the security warnings
    __supress_security()

    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    s = requests.Session()
    s.auth = (ntnxapi_data['username'], ntnxapi_data['password'])
    s.headers.update({'Content-Type': 'application/json; charset=utf-8'})

    return json.dumps(s.get(base_url, verify=False).json(), sort_keys=True)


def __http_post(base_url, json_data):
    # supress the security warnings
    __supress_security()

    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    s = requests.Session()
    s.auth = (ntnxapi_data['username'], ntnxapi_data['password'])
    s.headers.update({'Content-Type': 'application/json; charset=utf-8'})
    s.post(base_url, data=json_data, verify=False)

    return 0


def __request_vm_uuid(vmname):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + \
        "/vms/?count=1&searchString=" + vmname

    return str(json.loads(__htpp_request(base_url))['entities'][0]['uuid'])


def __request_vm_uuid_new(vmname):

    for i in __retrieve_config_data()['cluster'].split(','):
        base_url = "https://" + i + API_PRISM + \
            "/vms/?searchString=" + vmname
        # check if json_object has no entities before proceeding
        if json.loads(__htpp_request(base_url))['metadata']['count'] > 0:
            if vmname == str(json.loads(__htpp_request(base_url))['entities'][0][vmName]):
                break

    return str(json.loads(__htpp_request(base_url))['entities'][0]['uuid'])


def __request_vm_vmuuid(name):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + "/vms/?searchString=" + name

    return str(json.loads(__htpp_request(base_url))['entities'][0][vmId])


def __request_host_uuid(name):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data[
            'cluster'] + API_PRISM + "/hosts/?searchString=" + name

    return str(json.loads(__htpp_request(base_url))['entities'][0]['uuid'])


def __request_host_uuid_new(host_name):

    for i in __retrieve_config_data()['cluster'].split(','):
        base_url = "https://" + i + API_PRISM + \
            "/hosts/?searchString=" + host_name
        # check if json_object has no entities before proceeding
        if json.loads(__htpp_request(base_url))['metadata']['count'] > 0:
            if host_name == str(json.loads(__htpp_request(base_url))['entities'][0]['name']):
                break

    return str(json.loads(__htpp_request(base_url))['entities'][0]['uuid'])


def __request_cluster_uuid(name):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data[
            'cluster'] + API_PRISM + "/clusters/?searchString=" + name

    return str(json.loads(__htpp_request(base_url))['entities'][0]['uuid'])


def __request_cluster_uuid_new(cluster_name):

    for i in __retrieve_config_data()['cluster'].split(','):
        base_url = "https://" + i + API_PRISM + "/cluster"
        if cluster_name == str(json.loads(__htpp_request(base_url))['name']):
            break

    return str(json.loads(__htpp_request(base_url))['uuid'])


def __request_cluster_ip(cluster_name):

    for i in __retrieve_config_data()['cluster'].split(','):
        base_url = "https://" + i + API_PRISM + "/cluster"
        if cluster_name == str(json.loads(__htpp_request(base_url))['name']):
            break

    if API_VERSION == '1.0':
        return str(json.loads(__htpp_request(base_url))['clusterExternalIPAddress'])
    elif API_VERSION == '2.0':
        return str(json.loads(__htpp_request(base_url))['cluster_external_ipaddress'])        


def __request_hosts(cluster_ip_address):

    base_url = "https://" + cluster_ip_address + API_PRISM + "/hosts/"

    return __htpp_request(base_url)


def __request_cluster_hosts(cluster_ip_address):

    base_url = "https://" + cluster_ip_address + API_PRISM + "/hosts/"

    return __htpp_request(base_url)


def __request_vms(cluster_ip_address):

    base_url = "https://" + cluster_ip_address + API_PRISM + "/vms/"

    return __htpp_request(base_url)


def __request_clusters(cluster_ip_address):

    base_url = "https://" + cluster_ip_address + API_PRISM + "/clusters/"

    return __htpp_request(base_url)


def __request_cluster(uuid):

    for i in __retrieve_config_data()['cluster'].split(','):
        base_url = "https://" + i + API_PRISM + "/clusters/" + uuid
        if uuid == str(json.loads(__htpp_request(base_url))['uuid']):
            break

    return __htpp_request(base_url)


def __request_vm(uuid):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + "/vms/" + uuid

    return __htpp_request(base_url)


def __request_vm_by_name(vmname):

    vm_uuid = __request_vm_uuid_new(vmname)

    for i in __retrieve_config_data()['cluster'].split(','):
        base_url = "https://" + i + API_PRISM + "/vms/" + vm_uuid
        try:
            if vm_uuid == str(json.loads(__htpp_request(base_url))['uuid']):
                return json.loads(__htpp_request(base_url))
        except Exception, e:
            pass


def __request_host(uuid):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + "/hosts/" + uuid

    return __htpp_request(base_url)


def __request_host_vms(hostname):

    for i in __retrieve_config_data()['cluster'].split(','):
        base_url = "https://" + i + API_PRISM + "/hosts/?searchString=" + hostname
        # check if json_object has no entities before proceeding
        if json.loads(__htpp_request(base_url))['metadata']['count'] > 0:
            if hostname == str(json.loads(__htpp_request(base_url))['entities'][0]['name']):
                json_object = json.loads(__request_vms(i))
                return json_object


def __request_host_by_name(hostname):

    host_uuid = __request_host_uuid_new(hostname)

    for i in __retrieve_config_data()['cluster'].split(','):
        base_url = "https://" + i + API_PRISM + "/hosts/" + host_uuid
        try:
            if host_uuid == str(json.loads(__htpp_request(base_url))['uuid']):
                return json.loads(__htpp_request(base_url))
        except Exception, e:
            pass

# @deprecated
# def __request_vm_alert(uuid):
#     # request saved config data
#     ntnxapi_data = __retrieve_config_data()

#     base_url = "https://" + \
#         ntnxapi_data['cluster'] + API_PRISM + \
#         "/vms/" + uuid + "/alerts?resolved=false"

#     return __htpp_request(base_url)


# @deprecated
# def __request_host_alert(hostname):

#     host_uuid = __request_host_uuid_new(hostname)

#     for i in __retrieve_config_data()['cluster'].split(','):
#         base_url = "https://" + i + API_PRISM + \
#             "/hosts/" + host_uuid + "/alerts?resolved=false"

#         # check if json_object has no entities before proceeding
#         if json.loads(__htpp_request(base_url))['metadata']['count'] > 0:
#             return __htpp_request(base_url)


def __powerop_vm(uuid, operation):
    # supress the security warnings
    __supress_security()

    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    # request LogicalTimestampDTO for vm operations
    logicaltimestampdto = __request_logicaltimestampdtop_vm(uuid)
    json_data = json.dumps(
        {"logicalTimestamp": logicaltimestampdto}, sort_keys=True)

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_AHV + \
        "/vms/" + uuid + "/power_op/" + operation

    # request http post
    __http_post(base_url, json_data)

    # notify complete operation
    __notify('VM Power Operation', 'Virtual Machine Powering On/Off')


def __snapshot_vm(name):
    # supress the security warnings
    __supress_security()

    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    # request vm uuid
    uuid = __request_vm_uuid(name)

    # request vm vmId
    vmuuid = __request_vm_vmuuid(name)

    # retrieve timestamp for use in snapshotName
    snapshottimestamp = datetime.datetime.fromtimestamp(
        time.time()).strftime('%Y-%m-%d %H:%M:%S')

    # build snapshotSpecs payload
    children = []
    children.append({"vmUuid": vmuuid,
                     'snapshotName': snapshottimestamp,
                     "uuid": uuid})
    container = {}
    container['snapshotSpecs'] = children
    json_data = json.dumps(container)

    base_url = "https://" + ntnxapi_data['cluster'] + API_AHV + "/snapshots/"

    # request http post
    __http_post(base_url, json_data)

    #  complete operation
    __notify('VM Power Operation', 'VM snapshot complete')


def __enter_maintenance_mode_host(uuid):
    # supress the security warnings
    __supress_security()

    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    # POWER_OFF, COLD_MIGRATE, LIVE_MIGRATE
    json_data = json.dumps(
        {"evacuationOption": 'LIVE_MIGRATE',
         "logicalTimestamp": ''}, sort_keys=True)

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_AHV + \
        "/hosts/" + uuid + "/enter_maintenance_mode"

    # request http post
    __http_post(base_url, json_data)

    # notify complete operation
    __notify('Host Operation', 'Entering Maintenance Mode w/ LIVE_MIGRATE')


def __exit_maintenance_mode_host(uuid):
    # supress the security warnings
    __supress_security()

    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    json_data = json.dumps(
        {"logicalTimestamp": ''}, sort_keys=True)

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_AHV + \
        "/hosts/" + uuid + "/exit_maintenance_mode"

    # request http post
    __http_post(base_url, json_data)

    # notify complete operation
    __notify('Host Operation', 'Exiting Maintenance Mode')


def __notify(title, text):
    # issue Alfred notification banner
    notify(title=title, text=text, sound=None)
    return 0


def __check_update():
    # self-updating function
    wf.check_update(UPDATE_SETTINGS)
    if wf.update_available:
        # add list item for proceed with update
        wf.add_item(
            'New version available', 'Action this item to install the update',
            autocomplete='workflow:update',
            valid=False, icon=ICON_INFO
        )


def __parse_args_query(argument):

    # parse secondary query argument
    try:
        switcher = {
            'alerts': 'alerts',
            'snapshot': 'snapshot',
            'enter_maintenance_mode': 'enter_maintenance_mode',
            'exit_maintenance_mode': 'exit_maintenance_mode',
            '': 'no argument'
        }
    except Exception, e:
        raise e

    return switcher.get(argument, 'loaditem')


def __include_list_options(clusters, hosts, vms, hostvms, clusterhosts, alerts, argument, uid):

    if clusters:
        # include clusters option
        wf.add_item("clusters", valid=False,
                    autocomplete="clusters ", uid=u'clusters', icon=ICON_INFO)

    if hosts:
        # include hosts option
        wf.add_item("hosts", valid=False, autocomplete="hosts ",
                    uid=u'hosts', icon=ICON_INFO)

    if vms:
        # include vms option
        wf.add_item(
            "vms", valid=False, autocomplete="vms ", uid=u'vms', icon=ICON_INFO)

    if hostvms:
        # include host-vms option
        wf.add_item("host-vms", valid=False, autocomplete="host-vms " +
                    argument, uid=uid, icon=ICON_INFO)

    if clusterhosts:
        # include cluster-hosts option
        wf.add_item("cluster-hosts", valid=False, autocomplete="cluster-hosts " +
                    argument, uid=uid, icon=ICON_INFO)

    if alerts:
        # include alerts option
        wf.add_item("Alerts", valid=False, autocomplete="hosts alerts " +
                    argument, arg=uid, icon=ICON_NOTE)


def main(wf):
    # self-updating function
    __check_update()

    # define Nutanix API version to be used
    __define_api_version()

    # include Alfred list options
    # (clusters,hosts,vms,hostvms,clusterhosts,alerts,argument,uid)
    __include_list_options(
        True, True, True, False, False, False, 'null', 'null')

    args = parse_args(wf.args)

    # check for existing aguments in query
    if args.query is None:
        print "No argument provided"
        return 0

    if args.get:
        #
        # vm operations
        #
        if str((args.query).split(" ")[0]) == 'vms':
            # parse second args.query
            try:
                arg_secondary = __parse_args_query(
                    str((args.query).split(" ")[1]))
            except Exception:
                arg_secondary = 'no argument'

            # @deprecated
            # if arg_secondary == 'alerts':
            #     # uuid variable
            #     uuid = __request_vm_uuid(str((args.query).split(" ")[2]))

            #     # load and display alerts for a specific vm
            #     json_object = json.loads(__request_vm_alert(uuid))

            #     # check if json_object has no entities before proceeding
            #     if json_object['metadata']['count'] > 0:

            #         # iterate json result and add vm details to list
            #         for key, value in json_object['entities'].items():
            #             wf.add_item(
            #                 key + " : " + str(value), valid=False, icon=ICON_WARNING)
            #     else:
            #         wf.add_item(
            #             'No Alerts', valid=False, icon=ICON_WARNING)

            if arg_secondary == 'snapshot':
                __snapshot_vm(str((args.query).split(" ")[2]))

            if arg_secondary == 'loaditem':

                json_object = __request_vm_by_name(
                    str((args.query).split(" ")[1]))

                # add poweron switch (workflow defined 'alt' as poweroff)
                wf.add_item(
                    "PowerOn", valid=True, arg=str(json_object['uuid']), icon=ICON_SWITCH)

                # @deprecated
                # add alerts switch
                # wf.add_item(
                #     "Alerts", valid=False, autocomplete="vms alerts " +
                #     str((args.query).split(" ")[1]), arg=str(json_object['uuid']), icon=ICON_NOTE)

                # add clone switch
                wf.add_item(
                    "Snapshot", valid=False, autocomplete="vms snapshot " +
                    str((args.query).split(" ")[1]), arg=str(json_object['uuid']), icon=ICON_SNAPSHOT)

                # add vm state and display proper icon
                if json_object[powerstate] == 'on':
                    wf.add_item(
                        "State : " + json_object[powerstate], valid=False, icon=ICON_ON)
                else:
                    wf.add_item(
                        "State : " + json_object[powerstate], valid=False, icon=ICON_OFF)

                # iterate json result and add vm details to list
                for key, value in json_object.items():
                    # do not display certain keys
                    if key not in KEY_IGNORE_VM:
                        wf.add_item(
                            key + " : " + str(value), valid=False, icon=ICON_SETTINGS)

            if arg_secondary == 'no argument':

                # remove environment variabled given no selection
                __reset_env_variable('cluster.name')
                __reset_env_variable('host.name')

                for i in __retrieve_config_data()['cluster'].split(','):

                    # load and display all vms
                    json_object = json.loads(__request_vms(i))

                    for i in json_object['entities']:
                        # add vm state and display proper icon
                        if i[powerstate] == 'on':
                            wf.add_item(i[vmName], i['uuid'], valid=False, autocomplete="vms "
                                        + str(i[vmName]), uid=i['uuid'], icon=ICON_AHV_ON)
                        else:
                            wf.add_item(i[vmName], i['uuid'], valid=False, autocomplete="vms "
                                        + str(i[vmName]), uid=i['uuid'], icon=ICON_AHV)

        #
        # host operations
        #
        elif str((args.query).split(" ")[0]) == 'hosts':

            try:
                arg_secondary = __parse_args_query(
                    str((args.query).split(" ")[1]))
            except Exception:
                arg_secondary = 'no argument'

            # @deprecated
            # if arg_secondary == 'alerts':

            #     # load host
            #     json_object = json.loads(__request_host_alert(
            #         str((args.query).split(" ")[2])))

            #     # iterate json and add alerts to list
            #     for i in json_object['entities']:
            #         wf.add_item(
            #             i['alertTitle'], valid=True, icon=ICON_ERROR)


            if arg_secondary == 'loaditem':

                # save host.name for post use
                __save_env_variable('host.name', str((args.query).split(" ")[1]))

                # load and display a specify host
                json_object = __request_host_by_name(
                    str((args.query).split(" ")[1]))

                # include Alfred list options
                # (clusters,hosts,vms,hostvms,clusterhosts,alerts,argument,uid)
                __include_list_options(
                    False, False, False, True, False, False, str((args.query).split(" ")[1]), u'uuid')

                if ((json_object)['state']) == "NORMAL":
                    wf.add_item(
                        str("State :" + (json_object)['state']), icon=ICON_NORMAL)
                else:
                    wf.add_item(
                        str("State :" + (json_object)['state']), valid=False, icon=ICON_ERROR)

                # include enter_maintenance_mode and exit_maintenance_mode options
                # only include if Acropolis hypervisor
                if str((json_object)[hypervisorType]) == 'kKvm':
                    if str((json_object)[hypervisorState]) == 'kAcropolisNormal':
                        wf.add_item(
                            "Enter Maintenance Mode", valid=False,
                            autocomplete="hosts enter_maintenance_mode " +
                            str((args.query).split(" ")[1]), arg=str(json_object['uuid']), icon=ICON_MAINTENANCE)
                    elif str((json_object[hypervisorState])) == 'kEnteredMaintenanceMode':
                        wf.add_item(
                            "Exit Maintenance Mode", valid=False,
                            autocomplete="hosts exit_maintenance_mode " +
                            str((args.query).split(" ")[1]), arg=str(json_object['uuid']), icon=ICON_MAINTENANCE)

                # iterate json result and add host details to list
                for key, value in json_object.items():
                    # do not display certain keys
                    if key not in KEY_IGNORE_HOST:
                        wf.add_item(
                            key + " : " + str(value), valid=False, icon=ICON_SETTINGS)

            if arg_secondary == 'enter_maintenance_mode':
                # uuid variable
                uuid = __request_host_uuid_new(str((args.query).split(" ")[2]))

                # __enter_maintenance_mode_host
                __enter_maintenance_mode_host(uuid)

            if arg_secondary == 'exit_maintenance_mode':
                # uuid variable
                uuid = __request_host_uuid_new(str((args.query).split(" ")[2]))

                # __exit_maintenance_mode_host
                __exit_maintenance_mode_host(uuid)

            if arg_secondary == 'no argument':

                # remove environment variabled given no selection
                __reset_env_variable('cluster.name')
                __reset_env_variable('host.name')

                for i in __retrieve_config_data()['cluster'].split(','):
                    # load and display all clusters
                    json_object = json.loads(__request_hosts(i))

                    # iterate json result and add hosts to list
                    for i in json_object['entities']:
                        # load host icon based on host state
                        if i[hypervisorState] == 'kEnteredMaintenanceMode':
                            wf.add_item(i['name'], i['uuid'], valid=False, autocomplete="hosts " +
                                        str(i['name']), icon=ICON_AHV_AMBER)
                        elif i['state'] == 'NORMAL':
                            wf.add_item(i['name'], i['uuid'], valid=False, autocomplete="hosts " +
                                        str(i['name']), icon=ICON_AHV_ON)
                        else:
                            wf.add_item(i['name'], i['uuid'], valid=False, autocomplete="hosts " +
                                        str(i['name']), icon=ICON_AHV_ALERT)

        #
        # cluster operations
        #
        elif str((args.query).split(" ")[0]) == 'clusters':

            try:
                arg_secondary = __parse_args_query(
                    str((args.query).split(" ")[1]))
            except Exception:
                arg_secondary = 'no argument'

            if arg_secondary == 'loaditem':

                # save cluster.name variable for post use
                __save_env_variable('cluster.name', (args.query).split(" ")[1])

                # uuid variable
                uuid = __request_cluster_uuid_new(
                    str((args.query).split(" ")[1]))

                # include Alfred list options
                # (clusters,hosts,vms,hostvms,clusterhosts,alerts,argument,uid)
                __include_list_options(
                    False, False, False, False, True, False, str((args.query).split(" ")[1]), u'uuid')

                # load and display a specific cluster
                json_object = json.loads(__request_cluster(uuid))

                # notify('',str(json_object['uuid']))
                # iterate json result and add host details to list
                for key, value in json_object.items():
                    # do not display certain keys
                    if key not in KEY_IGNORE_CLUSTER:
                        wf.add_item(
                            key + " : " + str(value), valid=False, icon=ICON_SETTINGS)

            if arg_secondary == 'no argument':

                # remove environment variabled given no selection
                __reset_env_variable('cluster.name')
                __reset_env_variable('host.name')

                for i in __retrieve_config_data()['cluster'].split(','):
                    # load and display all clusters
                    json_object = json.loads(__request_clusters(i))

                    # iterate json result and add clusters to list
                    for i in json_object['entities']:
                        wf.add_item(i['name'], i['uuid'], valid=False, autocomplete="clusters " +
                                    str(i['name']), uid=i['uuid'], icon=ICON_AHV_ON)

        #
        # host-vm operations
        #
        elif str((args.query).split(" ")[0]) == "host-vms":

            # add 'Back' button option
            wf.add_item("Back", valid=False, autocomplete="hosts " +
                        __retrieve_env_variable('host.name'), icon=ICON_BACK)

            # uuid variable
            uuid = __request_host_uuid_new(str((args.query).split(" ")[1]))

            # load all vms
            json_object = __request_host_vms(str((args.query).split(" ")[1]))

            # iterate json result and add vms wher host 'uuid' match
            for i in json_object['entities']:
                try:
                    if i[hostUuid] == uuid:
                        # add vm state and display proper icon
                        if i[powerstate] == 'on':
                            wf.add_item(i[vmName], i['uuid'], valid=False, autocomplete="vms "
                                        + str(i[vmName]), uid=i['uuid'], icon=ICON_AHV_ON)
                        else:
                            wf.add_item(i[vmName], i['uuid'], valid=False, autocomplete="vms "
                                        + str(i[vmName]), uid=i['uuid'], icon=ICON_AHV)
                except Exception:
                    pass

        #
        # cluster-hosts operations
        #
        elif str((args.query).split(" ")[0]) == "cluster-hosts":

            # add 'Back' button option
            wf.add_item("Back", valid=False, autocomplete="clusters " +
                        __retrieve_env_variable('cluster.name'), icon=ICON_BACK)

            # cluster ip variable
            cluster_ip_address = __request_cluster_ip(
                str((args.query).split(" ")[1]))

            # load all vms
            json_object = json.loads(
                __request_cluster_hosts(cluster_ip_address))

            # iterate json result and add hosts where cluster 'uuid' match
            for i in json_object['entities']:
                try:
                    # load host icon based on host state
                    if i['state'] == 'NORMAL':
                        wf.add_item(i['name'], i['uuid'], valid=False, autocomplete="hosts " +
                                    str(i['name']), icon=ICON_AHV_ON)
                    else:
                        wf.add_item(i['name'], i['uuid'], valid=False, autocomplete="hosts " +
                                    str(i['name']), icon=ICON_AHV_ALERT)

                except Exception:
                    pass

    elif args.poweroff:
        # execute poweroff operation
        __powerop_vm(args.query, "off")

    elif args.poweron:
        # execute poweron operation
        __powerop_vm(args.query, "on")

    else:
        # notify error if conditions are not met
        __notify('Error', 'An error has occured')

    wf.send_feedback()


def parse_args(args):
    """parse --{option} arguments profided by workflow"""

    parser = argparse.ArgumentParser()
    parser.add_argument('--get', dest='get', action='store_true', default=None)
    parser.add_argument(
        '--poweroff', dest='poweroff', action='store_true', default=None)
    parser.add_argument(
        '--poweron', dest='poweron', action='store_true', default=None)
    parser.add_argument('query', nargs='?', default=None)

    return parser.parse_args(args)


if __name__ == u"__main__":

    global wf  # global workflow Alfred varibale

    # install and import modules
    # 'pip install --user -U pip' must be execute beforehand
    __install_and_import_package('requests')
    __install_and_import_package('json')

    wf = Workflow(update_settings=UPDATE_SETTINGS)
    sys.exit(wf.run(main))

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
from workflow import Workflow, ICON_SWITCH, ICON_INFO, ICON_SETTINGS, ICON_NOTE, ICON_WARNING, \
    ICON_ERROR
from workflow.notify import notify


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
ICON_AHV_ALERT = 'icons/ahv_alert.png'
ICON_CLONE = 'icons/clone.png'
ICON_SNAPSHOT = 'icons/snapshot.png'


# Nutanix API URI
API_AHV = ':9440/api/nutanix/v0.8'
API_PRISM = ':9440/PrismGateway/services/rest/v1'


# Filter ignore Keys
KEY_IGNORE_VM = {'vmDisks', 'vmNics'}
KEY_IGNORE_HOST = {'dynamicRingChangingNode', 'keyManagementDeviceToCertificateStatus',
                   'stats', 'diskHardwareConfigs', 'usageStats', 'position', 'state',
                   'hostNicIds', 'hasCsr', 'vzoneName', 'bootTimeInUsecs', 'defaultVhdLocation',
                   'defaultVhdContainerId', 'removalStatus', 'defaultVmContainerUuid',
                   'defaultVhdContainerUuid', 'defaultVmLocation'}
KEY_IGNORE_CLUSTER = {'stats', 'usageStats', 'hypervisorSecurityComplianceConfig',
                      'securityComplianceConfig', 'rackableUnits', 'publicKeys', 
                      'clusterRedundancyState', 'globalNfsWhiteList'}


def __install_and_import_package(package):
    import importlib
    try:
        importlib.import_module(package)
    except ImportError:
        import pip
        pip.main(['install', '--user', package])
    finally:
        globals()[package] = importlib.import_module(package)


def __supress_security():
    # supress the security warnings
    requests.packages.urllib3.disable_warnings()


def __retrieve_config_data():
    # request saved config data
    return wf.stored_data('ntnxapi_data')


def __request_logicaltimestampdtop(uuid):
    # request LogicalTimestampDTO for vm operations
    json_object = json.loads(__request_vm(str(uuid)))

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


def __request_vm_uuid(name):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + "/vms/?searchString=" + name

    return str(json.loads(__htpp_request(base_url))['entities'][0]['uuid'])


def __request_vm_vmuuid(name):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + "/vms/?searchString=" + name

    return str(json.loads(__htpp_request(base_url))['entities'][0]['vmId'])


def __request_host_uuid(name):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data[
            'cluster'] + API_PRISM + "/hosts/?searchString=" + name

    return str(json.loads(__htpp_request(base_url))['entities'][0]['uuid'])


def __request_cluster_uuid(name):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data[
            'cluster'] + API_PRISM + "/clusters/?searchString=" + name

    return str(json.loads(__htpp_request(base_url))['entities'][0]['uuid'])


def __request_hosts():
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + "/hosts/"

    return __htpp_request(base_url)


def __request_vms():
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_AHV + "/vms/"

    return __htpp_request(base_url)


def __request_clusters():
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + "/clusters/"

    return __htpp_request(base_url)


def __request_vm(uuid):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_AHV + "/vms/" + uuid

    return __htpp_request(base_url)


def __request_host(uuid):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + "/hosts/" + uuid

    return __htpp_request(base_url)


def __request_cluster(uuid):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + "/clusters/" + uuid

    return __htpp_request(base_url)


def __request_vm_alert(uuid):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + \
        "/vms/" + uuid + "/alerts?resolved=false"

    return __htpp_request(base_url)


def __request_host_alert(uuid):
    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_PRISM + \
        "/hosts/" + uuid + "/alerts?resolved=false"

    return __htpp_request(base_url)


def __powerop_vm(uuid, operation):
    # supress the security warnings
    __supress_security()

    # request saved config data
    ntnxapi_data = __retrieve_config_data()

    # request LogicalTimestampDTO for vm operations
    logicaltimestampdto = __request_logicaltimestampdtop(uuid)
    json_data = json.dumps(
        {"logicalTimestamp": logicaltimestampdto}, sort_keys=True)

    base_url = "https://" + \
        ntnxapi_data['cluster'] + API_AHV + \
        "/vms/" + uuid + "/power_op/" + operation
    s = requests.Session()
    s.auth = (ntnxapi_data['username'], ntnxapi_data['password'])
    s.headers.update({'Content-Type': 'application/json; charset=utf-8'})
    s.post(base_url, data=json_data, verify=False)

    # notify complete operation via Alfred workflow
    notify(title=u'VM Power Operations',
           text=u"Virtual Machine Powering On/Off", sound=None)


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

    # build snapshotSpecs paylod
    children = []
    children.append({"vmUuid": vmuuid,
                     'snapshotName': snapshottimestamp,
                     "uuid": uuid})
    container = {}
    container['snapshotSpecs'] = children
    json_data = json.dumps(container)

    base_url = "https://" + ntnxapi_data['cluster'] + API_AHV + "/snapshots/"
    s = requests.Session()
    s.auth = (ntnxapi_data['username'], ntnxapi_data['password'])
    s.headers.update({'Content-Type': 'application/json; charset=utf-8'})
    s.post(base_url, data=json_data, verify=False)

    # notify complete operation via Alfred workflow
    notify(title=u'VM Operations', text=u'VM snapshot complete', sound=None)


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
            '': 'no argument'
        }
    except Exception, e:
        raise e

    return switcher.get(argument, 'loaditem')


def main(wf):
    # self-updating function
    __check_update()

    args = parse_args(wf.args)

    # check for existing aguments in query
    if args.query is None:
        print "No argument provided"
        return 0

    if args.notifications:
        notify(title=u'Notifications', text='Notifications', sound=None)
        return 0

    if args.get:
        # include clusters option
        wf.add_item(
            "clusters", valid=False, autocomplete="clusters ", uid=u'clusters', icon=ICON_INFO)

        # include hosts option
        wf.add_item("hosts", valid=False, autocomplete="hosts ",
                    uid=u'hosts', icon=ICON_INFO)

        # include vms option
        wf.add_item(
            "vms", valid=False, autocomplete="vms ", uid=u'vms', icon=ICON_INFO)

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

            if arg_secondary == 'alerts':
                # uuid variable
                uuid = __request_vm_uuid(str((args.query).split(" ")[2]))

                # load and display alerts for a specific vm
                json_object = json.loads(__request_vm_alert(uuid))

                # check if json_object has no entities before proceeding
                if json_object['metadata']['count'] > 0:

                    # iterate json result and add vm details to list
                    for key, value in json_object['entities'].items():
                        wf.add_item(
                            key + " : " + str(value), valid=False, icon=ICON_WARNING)
                else:
                    wf.add_item(
                        'No Alerts', valid=False, icon=ICON_WARNING)

            if arg_secondary == 'snapshot':
                __snapshot_vm(str((args.query).split(" ")[2]))

            if arg_secondary == 'loaditem':
                # uuid variable
                uuid = __request_vm_uuid(str((args.query).split(" ")[1]))

                # load and display a specify vm
                json_object = json.loads(__request_vm(uuid))

                # add poweron switch (workflow defined 'alt' as poweroff)
                wf.add_item(
                    "PowerOn", valid=True, arg=uuid, icon=ICON_SWITCH)

                # add alerts switch
                wf.add_item(
                    "Alerts", valid=False, autocomplete="vms alerts " +
                    str((args.query).split(" ")[1]), arg=uuid, icon=ICON_NOTE)

                # add clone switch
                wf.add_item(
                    "Snapshot", valid=False, autocomplete="vms snapshot " +
                    str((args.query).split(" ")[1]), arg=uuid, icon=ICON_SNAPSHOT)

                # add vm state and display proper icon
                if json_object['state'] == 'on':
                    wf.add_item(
                        "State : " + json_object['state'], valid=False, icon=ICON_ON)
                else:
                    wf.add_item(
                        "State : " + json_object['state'], valid=False, icon=ICON_OFF)

                # iterate json result and add vm details to list
                for key, value in json_object['config'].items():
                    # do not display certain keys
                    if key not in KEY_IGNORE_VM:
                        wf.add_item(
                            key + " : " + str(value), valid=False, icon=ICON_SETTINGS)

            if arg_secondary == 'no argument':
                # load and display all vms
                json_object = json.loads(__request_vms())

                # iterate json result and add vms to list
                for i in json_object['entities']:
                    wf.add_item(i['config']['name'], i['uuid'], valid=False, autocomplete="vms "
                                + str(i['config']['name']), uid=i['uuid'], icon=ICON_AHV)

        # 
        # host operations
        # 
        elif str((args.query).split(" ")[0]) == 'hosts':

            try:
                arg_secondary = __parse_args_query(
                    str((args.query).split(" ")[1]))
            except Exception:
                arg_secondary = 'no argument'

            if arg_secondary == 'alerts':
                # uuid variable
                uuid = __request_host_uuid(str((args.query).split(" ")[2]))

                # load and display a specify host
                json_object = json.loads(__request_host_alert(uuid))

                # check if json_object has no entities before proceeding
                if json_object['metadata']['count'] > 0:

                    # iterate json result and add alerts to list
                    for i in json_object['entities']:
                        wf.add_item(
                            i['alertTitle'], valid=False, icon=ICON_ERROR)
                else:
                    wf.add_item(
                        'No Alerts', valid=False, icon=ICON_WARNING)

            if arg_secondary == 'loaditem':
                # uuid variable
                uuid = __request_host_uuid(str((args.query).split(" ")[1]))

                # load and display a specify host
                json_object = json.loads(__request_host(uuid))

                # include host-vms option
                wf.add_item("host-vms", valid=False, autocomplete="host-vms " +
                            str((args.query).split(" ")[1]), uid=u'uuid', icon=ICON_INFO)

                # add alerts switch
                wf.add_item(
                    "Alerts", valid=False, autocomplete="hosts alerts " +
                    str((args.query).split(" ")[1]), arg=uuid, icon=ICON_NOTE)

                if ((json_object)['state']) == "NORMAL":
                    wf.add_item(
                        str("State :" + (json_object)['state']), icon=ICON_NORMAL)
                else:
                    wf.add_item(
                        str("State :" + (json_object)['state']), valid=False, icon=ICON_ERROR)

                # iterate json result and add host details to list
                for key, value in json_object.items():
                    # do not display certain keys
                    if key not in KEY_IGNORE_HOST:
                        wf.add_item(
                            key + " : " + str(value), valid=False, icon=ICON_SETTINGS)

            if arg_secondary == 'no argument':
                # load and display all hosts
                json_object = json.loads(__request_hosts())

                # iterate json result and add hosts to list
                for i in json_object['entities']:
                    # load host icon based on host state
                    if i['state'] == 'NORMAL':
                        wf.add_item(i['name'], i['uuid'], valid=False, autocomplete="hosts " +
                                    str(i['name']), uid=i['uuid'], icon=ICON_AHV)
                    else:
                        wf.add_item(i['name'], i['uuid'], valid=False, autocomplete="hosts " +
                                    str(i['name']), uid=i['uuid'], icon=ICON_AHV_ALERT)

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
                # uuid variable
                uuid = __request_cluster_uuid(str((args.query).split(" ")[1]))

                # load and display a specific cluster
                json_object = json.loads(__request_cluster(uuid))

                # iterate json result and add host details to list
                for key, value in json_object.items():
                    # do not display certain keys
                    if key not in KEY_IGNORE_CLUSTER:
                        wf.add_item(
                            key + " : " + str(value), valid=False, icon=ICON_SETTINGS)

            if arg_secondary == 'no argument':
                # load and display all clusters
                json_object = json.loads(__request_clusters())

                # iterate json result and add clusters to list
                for i in json_object['entities']:
                    wf.add_item(i['name'], i['uuid'], valid=False, autocomplete="clusters " +
                                str(i['name']), uid=i['uuid'], icon=ICON_AHV)

        # 
        # host-vm operations
        # 
        elif str((args.query).split(" ")[0]) == "host-vms":

            # uuid variable
            uuid = __request_host_uuid(str((args.query).split(" ")[1]))

            # load all vms
            json_object = json.loads(__request_vms())

            # iterate json result and add vms wher host 'uuid' match
            for i in json_object['entities']:
                try:
                    if i['hostUuid'] == uuid:
                        wf.add_item(i['config']['name'], i['uuid'], valid=False,
                                    autocomplete="vms " + str(i['config']['name']), uid=i['uuid'],
                                    icon=ICON_AHV)
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
        notify(title=u'Error', text='An error occured', sound=None)

    wf.send_feedback()


def parse_args(args):
    """parse --{option} arguments profided by workflow"""

    parser = argparse.ArgumentParser()
    parser.add_argument('--get', dest='get', action='store_true', default=None)
    parser.add_argument(
        '--poweroff', dest='poweroff', action='store_true', default=None)
    parser.add_argument(
        '--poweron', dest='poweron', action='store_true', default=None)
    parser.add_argument(
        '--notifications', dest='notifications', action='store_true', default=None)
    parser.add_argument('query', nargs='?', default=None)

    return parser.parse_args(args)

if __name__ == u"__main__":

    global wf  # global workflow Alfred varibale
    global log  # global log variable

    # install and import modules
    # 'pip install --user -U pip' must be execute beforehand
    __install_and_import_package('requests')
    __install_and_import_package('json')

    wf = Workflow(update_settings=UPDATE_SETTINGS)
    log = wf.logger
    sys.exit(wf.run(main))

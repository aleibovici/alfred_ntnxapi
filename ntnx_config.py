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

import sys
import json
from ntnx_get import notify, parse_args
from workflow import Workflow

def main(wf):

    executed = False    # True if execution is sucessfull before store

    args = parse_args(wf.args)

    # include Alfred username option
    wf.add_item("username", valid=False,
                autocomplete="username ", uid=u'username')

    # include Alfred password option
    wf.add_item("password", valid=False,
                autocomplete="password ", uid=u'password')

    # include Alfred cluster option
    wf.add_item("cluster", valid=False,
                autocomplete="cluster ", uid=u'cluster')

    # check for existing aguments in query
    if args.query is None:
        notify('error', 'no arguments')
        return 0

    # load Alfred workflow configuration
    ntnxapi_data = json.loads(json.dumps(wf.stored_data('ntnxapi_data')))

    # Create ntnxapi_data if empty
    if ntnxapi_data == None:
        ntnxapi_data = {
            'cluster': {},
            'username': {},
            'password': {},
            'api': '1.0'
        }

    # granular control for each configuration entity
    if str((args.query).split(" ")[0]) == 'username':
        ntnxapi_data['username'] = str((args.query).split(" ")[1])
        executed = True

    if str((args.query).split(" ")[0]) == 'password':
        ntnxapi_data['password'] = str((args.query).split(" ")[1])
        executed = True

    if str((args.query).split(" ")[0]) == 'cluster':
        ntnxapi_data['cluster'] = str((args.query).split(" ")[1])
        executed = True

    if str((args.query).split(" ")[0]) == 'api':
        ntnxapi_data['api'] = str((args.query).split(" ")[1])
        executed = True

    if executed:
        # use Alfred to store workflow configuration
        wf.store_data('ntnxapi_data', ntnxapi_data, serializer='json')
        notify('Notice', 'Configuration Data Sucesfully Stored')

    wf.send_feedback()

if __name__ == u"__main__":

    global wf  # global workflow Alfred varibale

    wf = Workflow()
    sys.exit(wf.run(main))

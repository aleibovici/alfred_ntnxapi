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
from workflow import Workflow


def main(wf):
    """Save cluster configuration"""

    ntnxapi_data = wf.stored_data('ntnxapi_data')
    data = {}

    if ntnxapi_data is None:

        # Clear stored data
        wf.clear_data()

        data = {
            'cluster': str(sys.argv[1]).split(" ")[0],
            'username': str(sys.argv[1]).split(" ")[1],
            'password': str(sys.argv[1]).split(" ")[2],
        }

    wf.store_data('ntnxapi_data', data, serializer='json')
    ntnxapi_data = data

    wf.send_feedback()

if __name__ == u"__main__":
    wf = Workflow()
    sys.exit(wf.run(main))

#    __             _                ___  __  __
#    \ \  _____   _(_) __ _ _ __    /   \/ _\/ _\
#     \ \/ _ \ \ / / |/ _` | '_ \  / /\ /\ \ \ \
#  /\_/ / (_) \ V /| | (_| | | | |/ /_// _\ \_\ \
#  \___/ \___/ \_/ |_|\__,_|_| |_/____/  \__/\__/
#        _           _                 _      _
#    ___(_)_ __   __| | ___ _ __    __| |_ __(_)_   _____ _ __
#   / __| | '_ \ / _` |/ _ \ '__|  / _` | '__| \ \ / / _ \ '__|
#  | (__| | | | | (_| |  __/ |    | (_| | |  | |\ V /  __/ |
#   \___|_|_| |_|\__,_|\___|_|     \__,_|_|  |_| \_/ \___|_|
#
#
#    Copyright (c) 2016 Open-E, Inc.
#    All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.


import json

import urllib3

from oslo_log import log as logging

from cinder.volume.drivers.joviandss import common as jcom

LOG = logging.getLogger(__name__)


class JovianRESTProxy(object):
    """Jovian REST API proxy"""

    def __init__(self, config):
        
        self.url = config.jovian_rest_protocol + '://' +\
                   config.jovian_host + ':' +\
                   str(config.jovian_rest_port)

        self.user = config.jovian_user
        self.password = config.jovian_password

        self.verify = False
        self.retry_n = int(config.jovian_rest_send_repeats)

        self.pool = urllib3.PoolManager()

        self.header = urllib3.util.make_headers(
            basic_auth=str(self.user + ":" + self.password), keep_alive=True)
        self.header['Content-Type'] = 'application/json'

    def __call__(self, *args):
        pass

    def request(self, url, request_method, json_data=None):

        for i in range(self.retry_n):
            LOG.debug(
                "JovianDSS: Sending request of type {} to {}. \
                Attempt: {}.".format(request_method, url, i))
            try:

                ret = self.__request_routine(url, request_method, json_data)

                # Work aroud for case when we have backend internal Fail.
                #                                           OS Fail
                if ret["code"] == 500:
                    if ret["error"] is not None:
                        if ("errno" in ret["error"]) and \
                                ("class" in ret["error"]):
                            if (ret["error"]["errno"] is 2) and\
                                    (ret["error"]["class"] ==
                                         "exceptions.OSError"):
                                LOG.error(
                                    "JovianDSS: Facing exceptions.OSError!")
                                continue

                return ret
            except urllib3.exceptions.HTTPError as err:
                LOG.error("Unable to execute: {}".format(err))
                continue
            except urllib3.exceptions.NewConnectionError as err:
                LOG.error("Unable to execute: {}".format(err))

        raise jcom.JDSSRESTProxyException( \
            "Fail to execute {}, {} times in row.".format(url, self.retry_n))

    def __request_routine(self, url, request_method, json_data=None):
        """Make an HTTPS request and return the results
        """

        response_obj = self.pool.request(request_method,
                                         url,
                                         headers=self.header,
                                         body=json.dumps(json_data))

        LOG.debug('JovianDSS: Response code: %s' % response_obj.status)
        LOG.debug('JovianDSS: Response data: %s' % response_obj.data)

        ret = dict()
        ret['code'] = response_obj.status

        if response_obj.data is not None:
            if "error" in response_obj.data:
                ret["error"] = json.loads(response_obj.data)["error"]
            else:
                ret["error"] = None
            if "data" in response_obj.data:
                ret["data"] = json.loads(response_obj.data)["data"]
            else:
                ret["data"] = None

        return ret

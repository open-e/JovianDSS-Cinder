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

"""Network connection handling class for JovianDSS driver."""
from base64 import b64encode
from cinder.i18n import _
import json
import requests


from cinder import exception
from oslo_log import log as logging


LOG = logging.getLogger(__name__)


class JovianRESTProxy(object):
    """Jovian REST API proxy."""

    def __init__(self, config):
        """:param config: config is like dict."""
        self.user = config.get('jovian_user', 'admin')
        self.password = config.get('jovian_password', 'admin')
        self.retry_n = config.get('jovian_rest_send_repeats', 3)
        self.verify = False
        self.header = {'connection': 'keep-alive',
                       'Content-Type': 'application/json',
                       'authorization': 'Basic ' +
                       b64encode('%(username)s:%(password)s' %
                                 {'username': self.user,
                                  'password': self.password}).decode('utf-8')}

    def request(self, request_method, url, json_data=None):
        """Send request to the specific url.

        :param request_method: GET, POST, DELETE
        :param url: where to send
        :param json_data: data
        """
        for i in range(int(str(self.retry_n))):
            LOG.debug(
                "JovianDSS: Sending request of type %(type)s to %(url)s \
                Attempt: %(num)s.",
                {'type': request_method,
                 'url': url,
                 'num': i})

            if json_data is not None:
                LOG.debug(
                    "JovianDSS: Sending data: %s.", str(json_data))
            try:

                ret = self.request_routine(url, request_method, json_data)

                # Work aroud for case when we have backend internal Fail.
                #                                           OS Fail
                if ret["code"] == 500:
                    if ret["error"] is not None:
                        if ("errno" in ret["error"]) and \
                                ("class" in ret["error"]):
                            if (ret["error"]["errno"] is 2) and\
                                    (ret["error"]["class"] ==
                                        "exceptions.OSError"):
                                LOG.debug(
                                    "JovianDSS: Facing exceptions.OSError!")
                                continue

                return ret
            except requests.HTTPError as err:
                LOG.debug("Unable to execute: %s", err)
                continue
            except requests.ConnectionError as err:
                LOG.debug("Unable to execute: %s", err)

        msg = (_('%(times) faild in a row') % {'times': i})

        raise exception.JDSSRESTProxyException(host=url, reason=msg)

    def request_routine(self, url, request_method, json_data=None):
        """Make an HTTPS request and return the results."""
        response_obj = requests.request(request_method,
                                        url=url,
                                        headers=self.header,
                                        data=json.dumps(json_data),
                                        verify=self.verify)

        LOG.debug('JovianDSS: Response code: %s', response_obj.status_code)
        LOG.debug('JovianDSS: Response data: %s', response_obj.text)

        ret = dict()
        ret['code'] = response_obj.status_code

        if '{' in response_obj.text and '}' in response_obj.text:
            if "error" in response_obj.text:
                ret["error"] = json.loads(response_obj.text)["error"]
            else:
                ret["error"] = None
            if "data" in response_obj.text:
                ret["data"] = json.loads(response_obj.text)["data"]
            else:
                ret["data"] = None

        return ret

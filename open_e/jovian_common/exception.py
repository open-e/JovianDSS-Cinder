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

from cinder import exception
from cinder.i18n import _


class JDSSException(exception.VolumeDriverException):
    message = _("%(reason)s")


class JDSSRESTException(JDSSException):
    message = _("JDSS REST request %(request) faild: %(reason)s.")


class JDSSRESTProxyException(JDSSException):
    message = _("JDSS connection with %(host) failed: %(reason)s.")


class JDSSRESTResourceNotFoundException(JDSSException):
    message = _("JDSS unable to found resource %(message)s.")

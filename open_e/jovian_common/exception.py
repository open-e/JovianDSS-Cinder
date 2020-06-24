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
    """Unknown error"""
    message = _("%(reason)s")


class JDSSRESTException(JDSSException):
    """Unknown communication error"""

    message = _("JDSS REST request %(request)s faild: %(reason)s.")


class JDSSRESTProxyException(JDSSException):
    """Connection with host failed"""

    message = _("JDSS connection with %(host)s failed: %(reason)s.")


class JDSSResourceNotFoundException(JDSSException):
    """Unable to locate resource with specified id"""

    message = _("JDSS resource %(res)s DNE.")


class JDSSResourceExistsException(JDSSException):
    """Resource with specified id exists"""

    message = _("JDSS resource %(res)s DNE.")


class JDSSRESTVolumeDNEException(JDSSException):
    """Volume does not exist"""

    message = _("JDSS volume %(volume)s DNE.")


class JDSSRESTSnapshotExistsException(JDSSException):
    """Snapshot with the same id exists"""

    message = _("JDSS snapshot %(snapshot)s already exists.")


class JDSSRESTVolumeExistsException(JDSSException):
    """Volume with same id exists"""

    message = _("JDSS volume %(volume)s already exists.")


class JDSSRESTSnapshotIsBusyException(JDSSException):
    """Snapshot have dependent clones"""

    message = _("JDSS snapshot %(snapshot)s already exists.")

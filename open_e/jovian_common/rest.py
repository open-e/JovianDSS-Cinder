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


"""REST cmd interoperation class for JovianDSS driver."""
import re

from oslo_log import log as logging

from cinder import exception
from cinder.i18n import _
from cinder.volume.drivers.open_e.jovian_common import exception as jexc
from cinder.volume.drivers.open_e.jovian_common import rest_proxy

LOG = logging.getLogger(__name__)


class JovianRESTAPI(object):
    """Jovian REST API proxy."""

    def __init__(self, config):

        self.target_p = config.get('jovian_target_prefix')
        self.pool = config.safe_get('jovian_pool')
        self.rproxy = rest_proxy.JovianRESTProxy(config)

        self.resource_dne_msg = (
            re.compile(r'^Zfs resource: .* not found in this collection\.$'))

    def get_active_host(self):
        """Return address of currently used host."""
        return self.rproxy.get_active_host()

    def is_pool_exists(self):
        """is_pool_exists.

        GET
        /pools/<string:poolname>

        :param pool_name:
        :return: Bool
        """
        req = ""
        LOG.debug("check pool")

        resp = self.rproxy.pool_request('GET', req)

        if resp["code"] != 200 or resp["error"] is not None:
            return False

        return True

    def get_iface_info(self):
        """get_iface_info

        GET
        /network/interfaces
        :return list of internet ifaces
        """
        req = '/network/interfaces'

        LOG.debug("get network interfaces")

        resp = self.rproxy.request('GET', req)
        if (resp['error'] is None) and (resp['code'] == 200):
            return resp['data']
        raise jexc.JDSSRESTException(resp['error']['message'])

    def get_luns(self):
        """get_all_pool_volumes.

        GET
        /pools/<string:poolname>/volumes
        :param pool_name
        :return list of all pool volumes
        """
        req = '/volumes'

        LOG.debug("get all volumes")
        resp = self.rproxy.pool_request('GET', req)

        if resp['error'] is None and resp['code'] == 200:
            return resp['data']
        raise jexc.JDSSRESTException(resp['error']['message'])

    def create_lun(self, volume_name, volume_size, sparse=False):
        """create_volume.

        POST
        .../volumes

        :param volume_name:
        :param volume_size:
        :return:
        """
        volume_size_str = str(volume_size)
        jbody = {
            'name': volume_name,
            'size': volume_size_str,
            'sparse': sparse
        }

        req = '/volumes'

        LOG.debug("create volume %s", str(jbody))
        resp = self.rproxy.pool_request('POST', req, json_data=jbody)

        if resp["error"] is None and (
                resp["code"] == 200 or resp["code"] == 201):
            return

        if resp["error"] is not None:
            if resp["error"]["errno"] == str(5):
                raise jexc.JDSSRESTException(
                    'Failed to create volume. {}.'.format(
                        resp['error']['message']))

        raise jexc.JDSSRESTException('Failed to create volume.')

    def extend_lun(self, volume_name, volume_size):
        """create_volume.

        PUT /volumes/<string:volume_name>
        """
        req = '/volumes/' + volume_name
        volume_size_str = str(volume_size)
        jbody = {
            'size': volume_size_str
        }

        LOG.debug("jdss extend volume %(volume)s to %(size)s",
                  {"volume": volume_name,
                   "size": volume_size_str})
        resp = self.rproxy.pool_request('PUT', req, json_data=jbody)

        if resp["error"] is None and resp["code"] == 201:
            return

        if resp["error"] is not None:
            raise jexc.JDSSRESTException(
                'Failed to extend volume {}'.format(resp['error']['message']))

        raise jexc.JDSSRESTException('Failed to create volume.')

    def is_lun(self, volume_name):
        """is_lun.

        GET /volumes/<string:volumename>
        Returns True if volume exists. Uses GET request.
        :param pool_name:
        :param volume_name:
        :return:
        """
        req = '/volumes/' + volume_name

        LOG.debug("check volume %s", volume_name)
        ret = self.rproxy.pool_request('GET', req)

        if ret["error"] is None and ret["code"] == 200:
            return True
        return False

    def get_lun(self, volume_name):
        """get_lun.

        GET /volumes/<volume_name>
        :param volume_name:
        :return:
        {
            "data":
            {
                "origin": null,
                "referenced": "65536",
                "primarycache": "all",
                "logbias": "latency",
                "creation": "1432730973",
                "sync": "always",
                "is_clone": false,
                "dedup": "off",
                "used": "1076101120",
                "full_name": "Pool-0/v1",
                "type": "volume",
                "written": "65536",
                "usedbyrefreservation": "1076035584",
                "compression": "lz4",
                "usedbysnapshots": "0",
                "copies": "1",
                "compressratio": "1.00x",
                "readonly": "off",
                "mlslabel": "none",
                "secondarycache": "all",
                "available": "976432152576",
                "resource_name": "Pool-0/v1",
                "volblocksize": "131072",
                "refcompressratio": "1.00x",
                "snapdev": "hidden",
                "volsize": "1073741824",
                "reservation": "0",
                "usedbychildren": "0",
                "usedbydataset": "65536",
                "name": "v1",
                "checksum": "on",
                "refreservation": "1076101120"
            },
            "error": null
        }
        """
        req = '/volumes/' + volume_name

        LOG.debug("get volume %s info", volume_name)
        resp = self.rproxy.pool_request('GET', req)

        if resp['error'] is None and resp['code'] == 200:
            return resp['data']
        raise jexc.JDSSRESTException(resp['error']['message'])

    def modify_lun(self, volume_name, prop=None):
        """Update volume properties

        :prop volume_name: volume name
        :prop prop: dictionary
            {
                <property>: <value>
            }
        """

        req = '/volumes/' + volume_name

        resp = self.rproxy.pool_request('PUT', req, json_data=prop)

        if ((resp["code"] == 200) or
                (resp["code"] == 201) or
                (resp["code"] == 204)):
            LOG.debug(
                "volume %s updated", volume_name)
            return
        raise jexc.JDSSRESTResourceNotFoundException(volume_name)

    def make_readonly_lun(self, volume_name):
        """Set volume into read only mode

        :param: volume_name: volume name
        """
        prop = {"property_name": "readonly", "property_value": "on"}

        self.modify_property_lun(volume_name, prop)

    def modify_property_lun(self, volume_name, prop=None):
        """Change volume properties

        :prop: volume_name: volume name
        :prop: prop: dictionary of volume properties in format
                { "property_name": "<name of property>",
                  "property_value":"<value of a property>"}
        """

        req = '/volumes/{}/roperties'.format(volume_name)

        resp = self.rproxy.pool_request('PUT', req, json_data=prop)

        if resp["code"] == 201:
            LOG.debug(
                "volume %s properties updated", volume_name)
            return

        if resp["code"] == 500:
            if resp["error"] is not None:
                if resp["error"]["errno"] == 1:
                    raise jexc.JDSSRESTResourceNotFoundExceptionn(
                        res=volume_name)
                raise jexc.JDSSRESTException(request=req,
                                             reason=resp['error']['message'])
        raise jexc.JDSSRESTException(request=req, reason="unknown")

    def delete_lun(self, volume_name,
                   recursively_children=False,
                   recursively_dependents=False,
                   force_umount=False):
        """delete_volume.

        DELETE /volumes/<string:volumename>
        :param volume_name:
        :return:
        """
        if not self.is_lun(volume_name):
            return

        jbody = {}
        if recursively_children is True:
            jbody['recursively_children'] = True

        if recursively_dependents is True:
            jbody['recursively_dependents'] = True

        if force_umount is True:
            jbody['force_umount'] = True

        req = '/volumes/' + volume_name
        LOG.debug(("delete volume:%(vol)s "
                   "recursively children:%(args)s"),
                  {'vol': volume_name,
                   'args': jbody})

        if len(jbody) > 0:
            resp = self.rproxy.pool_request('DELETE', req, json_data=jbody)
        else:
            resp = self.rproxy.pool_request('DELETE', req)

        if ((resp["code"] == 200) or
                (resp["code"] == 201) or
                (resp["code"] == 204)):
            LOG.debug(
                "volume %s deleted", volume_name)
            return

        # Handle DNE case
        if resp["code"] == 404:
            LOG.debug(
                "volume %s do not exists, delition success", volume_name)
            return

        if resp["error"] is not None:
            if "errno" in resp["error"]:
                if resp["error"]["errno"] == 1:
                    return

        # Handle volume busy
        if resp["code"] == 500 and resp["error"] is not None:
            if resp["error"]["errno"] == 1000:
                LOG.warning(
                    "volume %s is busy", volume_name)
                raise exception.VolumeIsBusy(volume_name=volume_name)

        raise jexc.JDSSRESTException('Failed to delete volume.')

    def is_target(self, target_name):
        """is_target.

        GET /san/iscsi/targets/ target_name
        :param target_name:
        :return: Bool
        """
        req = '/san/iscsi/targets/' + target_name

        LOG.debug("check if targe %s exists", target_name)
        resp = self.rproxy.pool_request('GET', req)

        if resp["error"] is not None or not (
                resp["code"] == 200 or resp["code"] == 201):
            return False

        if "name" in resp["data"]:
            if resp["data"]["name"] == target_name:
                LOG.debug(
                    "target %s exists", target_name)
                return True

        return False

    def create_target(self,
                      target_name,
                      use_chap=False,
                      allow_ip=None,
                      deny_ip=None):
        """create_target.

        POST /san/iscsi/targets
        :param target_name:
        :param chap_cred:
        :param allow_ip:
        "allow_ip": [
                "192.168.2.30/0",
                "192.168.3.45"
            ],

        :return:
        """
        req = '/san/iscsi/targets'

        LOG.debug("create target %s", target_name)

        jdata = {"name": target_name, "active": False}

        jdata["incoming_users_active"] = use_chap

        if allow_ip is not None:
            jdata["allow_ip"] = allow_ip

        if deny_ip is not None:
            jdata["deny_ip"] = deny_ip

        resp = self.rproxy.pool_request('POST', req, json_data=jdata)

        if resp["error"] is None and resp["code"] == 201:
            return

        if resp["code"] == 409:
            raise jexc.JDSSResourceExistsException(res=target_name)

        msg = 'Failed to create target {}.'.format(resp['error']['message'])
        raise jexc.JDSSRESTException(reason=msg, request=req)

    def delete_target(self, target_name):
        """delete_target.

        DELETE /san/iscsi/targets/<target_name>
        :param pool_name:
        :param target_name:
        :return:
        """
        req = '/san/iscsi/targets/' + target_name

        LOG.debug("delete target %s", target_name)

        resp = self.rproxy.pool_request('DELETE', req)

        if ((resp["code"] == 200) or
                (resp["code"] == 201) or
                (resp["code"] == 204)):
            LOG.debug(
                "target %s deleted", target_name)
            return

        if (resp["code"] == 404) or \
                (resp["error"]["class"] == "werkzeug.exceptions.NotFound"):
            raise jexc.JDSSRESTResourceNotFoundException(res=target_name)

        msg = 'Failed to delete target {}'.format(target_name)
        raise jexc.JDSSRESTException(reason=msg, request=req)

    def modify_target(self, target_name, **kwargs):
        """modify_target.

        PUT /san/iscsi/targets/<target_name>
        :param target_name:
        :parameter
        {
            "name": "new_target_name",
            "active": True/False
            "incoming_users_active": True/False
            "outgoing_user": {
                            "password": "password",
                            "name": "mutual_user"
                            }
            "allow_ip": [
                "192.168.2.30/0",
                "192.168.3.45"
                    ],
            "deny_ip":  [
                "0.0.0.0/0"
                        ]
        }
        :return:
        """
        req = '/san/iscsi/targets/' + target_name

        resp = self.rproxy.pool_request('PUT', req, json_data=kwargs)

        if resp['error'] is not None or resp['code'] != 201:
            if resp['error']['message']:
                raise jexc.JDSSRESTException(
                    reason=resp['error']['message'],
                    request=req)
            raise jexc.JDSSRESTException(
                reqson='Something wrong',
                request=req)

    def get_target_ip_settings(self, target_name):
        """get_target_ip_settings

        GET /san/iscsi/targets/<target_name>
        Use GET to abtain allowed and deny ip lists
        :param target_name:
        :return:
        {
            "allow_ip": [
                "192.168.2.30/0",
                "192.168.3.45"
                    ],
            "deny_ip":  [
                "0.0.0.0/0"
                        ]
        }
        """
        req = '/san/iscsi/targets/' + target_name
        LOG.debug("get target %s settings", target_name)

        resp = self.rproxy.pool_request('GET', req)

        if resp['error'] is not None or not (
                resp['code'] == 200 or
                resp['code'] == 201):
            if resp['error']['message']:
                raise jexc.JDSSRESTException(reason=resp['error']['message'],
                                             request=req)
            raise jexc.JDSSRESTException(reason='Something wrong',
                                         request=req)

        return {
            'allow_ip': resp['data']['allow_ip'],
            'deny_ip': resp['data']['deny_ip']}

    def set_target_ip_settings(self, target_name, settings):
        """set_target_ip_settings

        PUT /san/iscsi/targets/<target_name>
        Use GET and PUT requests to update allowed and deny ip lists
        :param target_name:
        :param settings
        {
            "allow_ip": [
                "192.168.2.30/0",
                "192.168.3.45"
                    ],
            "deny_ip":  [
                "0.0.0.0/0"
                        ]
        }
        :return: Throws JDSSRESTException if fails
        """
        req = '/san/iscsi/targets/' + target_name

        resp = self.rproxy.pool_request('GET', req)

        if resp['error'] is not None or not (
                resp['code'] == 200 or
                resp['code'] == 201):

            if resp['error']['message']:
                raise jexc.JDSSRESTException(reason=resp['error']['message'],
                                             request=req)
            raise jexc.JDSSRESTException(reason='Something wrong',
                                         request=req)

        target_settings = resp['data']

        target_settings['allow_ip'] = settings['allow_ip']
        target_settings['deny_ip'] = settings['deny_ip']

        target_settings.pop('conflicted')

        LOG.debug("set target %s settings", target_name)
        resp = self.rproxy.pool_request('PUT', req, json_data=target_settings)

        if resp['error'] is not None or not (
                resp['code'] == 200 or
                resp['code'] == 201):
            if resp['error']['message']:
                raise jexc.JDSSRESTException(reason=resp['error']['message'],
                                             request=req)
            raise jexc.JDSSRESTException(reason='Something wrong',
                                         request=req)

    def create_target_user(self, target_name, chap_cred):
        """Set CHAP credentials for accees specific target.

        POST
        /san/iscsi/targets/<target_name>/incoming-users

        :param target_name:
        :param chap_cred:
        {
            "name": "target_user",
            "password": "3e21ewqdsacxz" --- 12 chars min
        }
        :return:
        """
        req = '/san/iscsi/targets/' + target_name + "/incoming-users"

        LOG.debug("add credentails to target %s", target_name)

        resp = self.rproxy.pool_request('POST', req, json_data=chap_cred)

        if resp["error"] is None and \
                (resp["code"] == 200 or
                 resp["code"] == 201 or
                 resp["code"] == 204):
            return

        if resp['code'] == 404:
            raise jexc.JDSSResourceNotFoundException(res=target_name)

        msg = 'Failed to set target user {}.'.format(resp['error']['message'])
        raise jexc.JDSSRESTException(reason=msg, request=req)

    def get_target_user(self, target_name):
        """Get name of CHAP user for accessing target

        GET
        /san/iscsi/targets/<target_name>/incoming-users

        :param target_name:
        """
        req = '/san/iscsi/targets/' + target_name + "/incoming-users"

        LOG.debug("get chap cred for target %s", target_name)

        resp = self.rproxy.pool_request('GET', req)

        if resp["error"] is None and resp["code"] == 200:
            return resp['data']

        if resp['code'] == 404:
            raise jexc.JDSSResourceNotFoundException(res=target_name)

        msg = 'Failed to get target user {}.'.format(resp['error']['message'])
        raise jexc.JDSSRESTException(reason=msg, request=req)

    def delete_target_user(self, target_name, user_name):
        """Delete CHAP user for target

        DELETE
        /san/iscsi/targets/<target_name>/incoming-users/<user_name>

        :param target_name: target name
        :param user_name: user name
        """
        req = '/san/iscsi/targets/{0}/incoming-users/{1}'.format(
            target_name, user_name)

        LOG.debug("remove credentails from target %s", target_name)

        resp = self.rproxy.pool_request('DELETE', req)

        if resp["error"] is None and resp["code"] == 204:
            return

        if resp['code'] == 404:
            raise jexc.JDSSResourceNotFoundException(res=target_name)

        msg = 'Failed to delete target user {}.'.format(
            resp['error']['message'])
        raise jexc.JDSSRESTException(reason=msg, request=req)

    def is_target_lun(self, target_name, lun_name):
        """is_target_lun.

        GET /san/iscsi/targets/<target_name>/luns/<lun_name>
        :param pool_name:
        :param target_name:
        :param lun_name:
        :return: Bool
        """
        req = '/san/iscsi/targets/' + target_name + "/luns/" + lun_name

        LOG.debug("check if volume %(vol)s is associated with %(tar)s",
                  {'vol': lun_name,
                   'tar': target_name})
        resp = self.rproxy.pool_request('GET', req)

        if resp["code"] == 404:
            return False

        if resp["error"] is not None:
            return False

        if resp["code"] != 200:
            return False

        if resp["data"] is None:
            return False

        if "name" not in resp["data"]:
            return False

        if resp["data"]["name"] != lun_name:
            return False
        LOG.debug("volume %(vol)s is associated with %(tar)s",
                  {'vol': lun_name,
                   'tar': target_name})

        return True

    def attach_target_vol(self, target_name, lun_name, lun_id=0):
        """attach_target_vol.

        POST /san/iscsi/targets/<target_name>/luns
        :param target_name:
        :param lun_name:
        :return:
        """
        req = '/san/iscsi/targets/' + target_name + "/luns"

        jbody = {"name": lun_name, "lun": str(lun_id)}
        LOG.debug("atach volume %(vol)s to target %(tar)s",
                  {'vol': lun_name,
                   'tar': target_name})

        resp = self.rproxy.pool_request('POST', req, json_data=jbody)

        if resp["error"] is None and resp["code"] == 201:
            return

        if resp['code'] == 409:
            raise jexc.JDSSResourceExistsException(res=lun_name)

        if resp['code'] == 404:
            raise jexc.JDSSResourceExistsException(res=target_name)

        raise jexc.JDSSRESTException(
            'Failed to attach volume {}.'.format(resp['error']['message']))

    def activate_target(self, target_name):
        """Set activate flag for target as True

        :param target_name: target name
        """
        req = '/san/iscsi/targets/{}'.format(target_name)

        LOG.debug("activate target %s", target_name)

        jdata = {"active": True}

        resp = self.rproxy.pool_request('PUT', req, json_data=jdata)

        if resp["error"] is None and resp["code"] == 200:
            return

        if resp['code'] == 404:
            raise jexc.JDSSRESTResourceNotFoundException(res=target_name)

        msg = 'Failed to activate target {} because {}.'.format(
            target_name, resp['error']['message'])
        raise jexc.JDSSRESTException(reason=msg, request=req)

    def deactivate_target(self, target):
        """Set activate flag for target as False

        :param target_name: target name
        """
        req = '/san/iscsi/targets/{}'.format(target)

        LOG.debug("deactivate target %s", target)

        jdata = {"active": False}

        resp = self.rproxy.pool_request('PUT', req, json_data=jdata)

        if resp["error"] is None and resp["code"] == 200:
            return

        if resp['code'] == 404:
            raise jexc.JDSSRESTResourceNotFoundException(res=target)

        msg = 'Failed to activate target {} because {}.'.format(
            target, resp['error']['message'])
        raise jexc.JDSSRESTException(reason=msg, request=req)

    def detach_target_vol(self, target_name, lun_name):
        """detach_target_vol.

        DELETE /san/iscsi/targets/<target_name>/luns/
        <lun_name>
        :param target_name:
        :param lun_name:
        :return:
        """
        req = '/san/iscsi/targets/' + target_name + "/luns/" + lun_name

        if not self.is_target_lun(target_name, lun_name):
            return

        LOG.debug("detach volume %(vol)s from target %(tar)s",
                  {'vol': lun_name,
                   'tar': target_name})

        resp = self.rproxy.pool_request('DELETE', req)

        if resp["code"] == 500 and \
                resp["error"]["class"] == \
                "opene.san.iscsi.TargetNotFoundError":
            return

        if resp["code"] == 500 and \
                resp["error"]["class"] == \
                "opene.san.iscsi.ZvolNotAssignedToTarget":
            return

        if (resp["code"] == 200) or \
                (resp["code"] == 201) or \
                (resp["code"] == 204):
            return

        raise jexc.JDSSRESTException("unable to detach lun.")

    def create_snapshot(self, volume_name, snapshot_name):
        """create_snapshot.

        POST /pools/<string:poolname>/volumes/<string:volumename>/snapshots
        :param pool_name:
        :param volume_name: source volume
        :param snapshot_name: snapshot name
        :return:
        """
        req = '/volumes/' + volume_name + '/snapshots'

        jbody = {
            'snapshot_name': snapshot_name
        }

        LOG.debug("create snapshot %s", snapshot_name)

        resp = self.rproxy.pool_request('POST', req, json_data=jbody)

        if (resp["error"] is None) and (
                (resp["code"] == 200) or
                (resp["code"] == 201) or
                (resp["code"] == 204)):
            return

        if resp["code"] == 500:
            if resp["error"] is not None:
                if resp["error"]["errno"] == 1:
                    raise jexc.JDSSRESTVolumeDNEException(
                        volume=volume_name)
                if resp["error"]["errno"] == 5:
                    raise jexc.JDSSRESTSnapshotExistsException(
                        snapshot=snapshot_name)
                msg = 'Failed to create snapshot {}, err: {}'.format(
                    snapshot_name, resp['error']['message'])
                raise jexc.JDSSRESTException(msg)

        msg = 'Failed to create snapshot {}'.format(snapshot_name)
        raise jexc.JDSSRESTException(msg)

    def create_volume_from_snapshot(self, volume_name, snapshot_name,
                                    original_vol_name, **options):
        """create_volume_from_snapshot.

        POST /volumes/<string:volumename>/clone
        :param volume_name: volume that is going to be created
        :param snapshot_name: slice of original volume
        :param original_vol_name: sample copy
        :return:
        """
        req = '/volumes/' + original_vol_name + '/clone'

        jbody = {
            'name': volume_name,
            'snapshot': snapshot_name,
            'sparse': False
        }

        if 'sparse' in options:
            jbody['sparse'] = options['sparse']

        LOG.debug("create volume %(vol)s from snapshot %(snap)s",
                  {'vol': volume_name,
                   'snap': snapshot_name})

        resp = self.rproxy.pool_request('POST', req, json_data=jbody)

        if resp["error"] is None and (
                (resp["code"] == 200) or
                (resp["code"] == 201) or
                (resp["code"] == 204)):
            return

        if resp["code"] == 500:
            if resp["error"] is not None:
                if resp["error"]["errno"] == 100:
                    raise jexc.JDSSRESTVolumeExistsException(
                        volume=volume_name)
                args = {"vol": volume_name, "e": resp['error']['message']}
                msg = _('Failed to create volume %(vol)s, err: %(e)s') % args
                raise jexc.JDSSRESTException(msg)

        raise jexc.JDSSRESTException('unable to create volume')

    def is_snapshot(self, volume_name, snapshot_name):
        """is_snapshots.

        GET
        /volumes/<string:volumename>/snapshots/<string:snapshotname>/clones

        :param volume_name: that snapshot belongs to
        :return: bool
        """
        req = '/volumes/' + volume_name + '/snapshots/' + snapshot_name + \
            '/clones'

        LOG.debug("check if snapshot %(snap)s of volume %(vol)s exists",
                  {'snap': snapshot_name,
                   'vol': volume_name})

        resp = self.rproxy.pool_request('GET', req)

        if resp["error"] is None and resp["code"] == 200:
            return True

        return False

    def delete_snapshot(self,
                        volume_name,
                        snapshot_name,
                        recursively_children=False,
                        recursively_dependents=False,
                        force_umount=False):
        """delete_snapshot.

        DELETE /volumes/<string:volumename>/snapshots/
            <string:snapshotname>
        :param volume_name: volume that snapshot belongs to
        :param snapshot_name: snapshot name
        :param recursively_children: boolean indicating if zfs should
            recursively destroy all children of resource, in case of snapshot
            remove all snapshots in descendant file system (default false).
        :param recursively_dependents: boolean indicating if zfs should
            recursively destroy all dependents, including cloned file systems
            outside the target hierarchy (default false).
        :param force_umount: boolean indicating if volume should be forced to
            umount (defualt false).
        :return:
        """
        if not self.is_snapshot(volume_name, snapshot_name):
            return

        req = '/volumes/' + volume_name + '/snapshots/' + snapshot_name

        LOG.debug("delete snapshot %(snap)s of volume %(vol)s",
                  {'snap': snapshot_name,
                   'vol': volume_name})

        jbody = {}
        if recursively_children is True:
            jbody['recursively_children'] = True

        if recursively_dependents is True:
            jbody['recursively_dependents'] = True

        if force_umount is True:
            jbody['force_umount'] = True

        resp = dict()
        if len(jbody) > 0:
            resp = self.rproxy.pool_request('DELETE', req, json_data=jbody)
        else:
            resp = self.rproxy.pool_request('DELETE', req)

        if ((resp["code"] == 200) or
                (resp["code"] == 201) or
                (resp["code"] == 204)):
            LOG.debug("snapshot %s deleted", snapshot_name)
            return

        if resp["code"] == 500:
            if resp["error"] is not None:
                if resp["error"]["errno"] == 1000:
                    raise jexc.JDSSRESTSnapshotIsBusyException(
                        snapshot=snapshot_name)
                msg = 'Failed to delete snapshot {}, err: {}'.format(
                    snapshot_name, resp['error']['message'])
                raise jexc.JDSSRESTException(msg)
        msg = 'Failed to delete snapshot {}'.format(snapshot_name)
        raise jexc.JDSSRESTException(msg)

    def get_snapshots(self, volume_name):
        """get_snapshots.

        GET
        /volumes/<string:volumename>/
            snapshots

        :param volume_name: that snapshot belongs to
        :return:
        {
            "data":
            [
                {
                    "referenced": "65536",
                    "name": "MySnapshot",
                    "defer_destroy": "off",
                    "userrefs": "0",
                    "primarycache": "all",
                    "type": "snapshot",
                    "creation": "2015-5-27 16:8:35",
                    "refcompressratio": "1.00x",
                    "compressratio": "1.00x",
                    "written": "65536",
                    "used": "0",
                    "clones": "",
                    "mlslabel": "none",
                    "secondarycache": "all"
                }
            ],
            "error": null
        }
        """
        req = '/volumes/' + volume_name + '/snapshots'

        LOG.debug("get snapshots for volume %s ", volume_name)

        resp = self.rproxy.pool_request('GET', req)

        if resp["error"] is None and resp["code"] == 200:
            return resp["data"]

        if resp['code'] == 500:
            if 'message' in resp:
                if self.resource_dne_msg.match(resp['message']):
                    raise jexc.JDSSRESTResourceNotFoundException(volume_name)
        raise jexc.JDSSRESTException('unable to get snapshots')

    def get_pool_stats(self):
        """get_pool_stats.

        GET /pools/<string:poolname>
        :param pool_name:
        :return:
        {
          "data": {
            "available": "24433164288",
            "status": 24,
            "name": "Pool-0",
            "scan": {
              "errors": 0,
              "repaired": "0",
              "start_time": 1463476815,
              "state": "finished",
              "end_time": 1463476820,
              "type": "scrub"
            },
            "iostats": {
              "read": "0",
              "write": "0",
              "chksum": "0"
            },
            "vdevs": [
              {
                "name": "scsi-SSCST_BIOoWKF6TM0qafySQBUd1bb392e",
                "iostats": {
                  "read": "0",
                  "write": "0",
                  "chksum": "0"
                },
                "disks": [
                  {
                    "led": "off",
                    "name": "sdb",
                    "iostats": {
                      "read": "0",
                      "write": "0",
                      "chksum": "0"
                    },
                    "health": "ONLINE",
                    "sn": "d1bb392e",
                    "path": "pci-0000:04:00.0-scsi-0:0:0:0",
                    "model": "oWKF6TM0qafySQBU",
                    "id": "scsi-SSCST_BIOoWKF6TM0qafySQBUd1bb392e",
                    "size": 30064771072
                  }
                ],
                "health": "ONLINE",
                "vdev_replacings": [],
                "vdev_spares": [],
                "type": ""
              }
            ],
            "health": "ONLINE",
            "operation": "none",
            "id": "11612982948930769833",
            "size": "29796335616"
          },
          "error": null
        }
        """
        req = ""
        LOG.debug("Get pool %s fsprops", self.pool)

        resp = self.rproxy.pool_request('GET', req)
        if resp["error"] is None and resp["code"] == 200:
            return resp["data"]

        raise jexc.JDSSRESTException('Unable to get pool info')

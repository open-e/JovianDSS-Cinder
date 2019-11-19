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

"""iSCSI volume driver for JovianDSS driver."""
import math
import random
import re
import six
import string

from cinder import exception
from cinder.i18n import _
from cinder.volume import driver
from cinder.volume.drivers.open_e.jovian_common import jdss_common as jcom
from cinder.volume.drivers.open_e.jovian_common import rest
from cinder.volume.drivers.open_e import options
from oslo_log import log as logging
from oslo_utils import netutils as o_netutils
from oslo_utils import units as o_units


LOG = logging.getLogger(__name__)


class JovianISCSIDriver(driver.ISCSIDriver):
    """Executes volume driver commands on Open-E JovianDSS V7."""

    # ThirdPartySystems wiki page
    CI_WIKI_NAME = "Open-E_JovianDSS_CI"
    VERSION = "1.0.1"

    def __init__(self, *args, **kwargs):
        super(JovianISCSIDriver, self).__init__(*args, **kwargs)

        self.re_tmp_snapshot = re.compile(r'tmp_snapshot:(.+),')

        self.ra = None
        self.conf = dict()

        LOG.debug('JovianDSS: Enter JovianISCSIDriver')
        self.configuration.append_config_values(
            options.jdss_connection_opts)
        self.configuration.append_config_values(
            options.jdss_iscsi_opts)
        self.configuration.append_config_values(
            options.jdss_volume_opts)

        pass

    @property
    def backend_name(self):
        """Return backend name."""
        backend_name = None
        if self.configuration:
            backend_name = self.configuration.safe_get('volume_backend_name')
        if not backend_name:
            backend_name = self.__class__.__name__
        return backend_name

    def do_setup(self, context):
        """Any initialization the volume driver does while starting."""
        self.jovian_iscsi_target_portal_port = str(
            self.configuration.safe_get('jovian_iscsi_target_portal_port'))
        self.conf['jovian_iscsi_target_portal_port'] = \
            self.jovian_iscsi_target_portal_port

        self.pool = self.configuration.safe_get('jovian_pool')
        self.conf['jovian_pool'] = self.pool

        self.jovian_target_prefix = self.configuration.safe_get(
            'jovian_target_prefix')
        self.conf['jovian_target_prefix'] = self.jovian_target_prefix

        self.jovian_target_group_prefix = self.configuration.safe_get(
            'jovian_target_group_prefix')
        self.conf['jovian_target_group_prefix'] = (
            self.jovian_target_group_prefix)

        self.jovian_chap_auth = self.configuration.safe_get('jovian_chap_auth')
        self.conf['jovian_chap_auth'] = self.jovian_chap_auth

        self.jovian_host = self.configuration.safe_get('jovian_host')
        self.conf['jovian_host'] = self.jovian_host

        self.conf['jovian_rest_port'] = self.configuration.safe_get(
            'jovian_rest_port')
        self.conf['jovian_rest_protocol'] = self.configuration.safe_get(
            'jovian_rest_protocol')
        self.conf['jovian_rest_send_repeats'] = self.configuration.safe_get(
            'jovian_rest_send_repeats')
        self.conf['jovian_user'] = self.configuration.safe_get(
            'jovian_user')
        self.conf['jovian_password'] = self.configuration.safe_get(
            'jovian_password')
        self.conf['jovian_ignore_tpath'] = self.configuration.safe_get(
            'jovian_ignore_tpath')

        for i in self.conf['jovian_ignore_tpath']:
            LOG.debug(i)

        self.jovian_chap_username = \
            self.configuration.safe_get('jovian_chap_username')
        self.conf['jovian_chap_username'] = self.configuration.safe_get(
            'jovian_chap_username')

        self.jovian_chap_pass_len = self.configuration.safe_get(
            'jovian_chap_pass_len')
        self.conf['jovian_chap_pass_len'] = self.jovian_chap_pass_len

        self.jovian_password_len = \
            self.configuration.safe_get('jovian_chap_pass_len')

        self.jovian_sparse = \
            self.configuration.safe_get('jovian_provisioning_thin')

        if o_netutils.is_valid_ip(self.jovian_host) is False:
            err_msg = ('JovianDSS: Invalid value of jovian_host property:'
                       '%(addr)s, IP address expected.' %
                       {'addr': self.jovian_host})

            LOG.debug(err_msg)
            raise exception.InvalidConfigurationValue(err_msg)

        self.ra = rest.JovianRESTAPI(self.conf)

        pass

    def check_for_setup_error(self):
        """Verify that the pool exists."""
        if not self.ra.is_pool_exists(self.pool):
            LOG.error("Setup is incorrect, please check connection settings.")
            raise exception.VolumeDriverException("Bad configuration expected")
    # TODO(andrei.perepiolkin@open-e.com): Provide additional checks

    def _get_zvol_name(self, volume_name):
        """Return zvol name that corresponds given volume name."""
        return '%s/%s' % (self.pool, volume_name)

    def _get_target_name(self, volume_name):
        """Return iSCSI target name to access volume."""
        return '%s%s' % (self.jovian_target_prefix, volume_name)

    def _get_target_group_name(self, volume_name):
        """Return JovianDSS iSCSI target group name for volume."""
        return '%s%s' % (self.jovian_target_group_prefix,
                         volume_name)

    def _get_active_ifaces(self):
        iface_info = self.ra.get_iface_info()
        if iface_info is None:
            LOG.debug('JovianDSS: Unable to get net interface info')

            raise exception.VolumeBackendAPIException(
                'JovianDSS: Unable to get net interface info')

        out = list()
        for iface in iface_info:

            if not iface['address']:
                continue

            if 'is_up' in iface:
                if not iface['is_up']:
                    continue

            if 'operational_state' in iface:
                if iface['operational_state'] != 'up':
                    continue

            if 'status' in iface:
                if iface['status'] != 'connected':
                    continue

            if self.conf['jovian_ignore_tpath']:
                if iface['address'] in self.conf['jovian_ignore_tpath']:
                    continue

            out.append(iface['address'])

        LOG.debug('JovianDSS: interfaces found %s', str(out))
        return out

    def create_volume(self, volume):
        """Create a volume.

        :param volume: volume reference
        :return: model update dict for volume reference
        """
        vname = volume['id']
        LOG.debug('JovianDSS: Creating volume %s.', volume['id'])

        provider_location = self._get_provider_location(vname)
        provider_auth = self._get_provider_auth()

        try:
            self.ra.create_lun(self.pool,
                               vname,
                               volume['size'] * o_units.Gi,
                               sparse=self.jovian_sparse)

        except exception.JDSSRESTException as ex:
            LOG.error("Create volume error. Because %(err).",
                      {"err": ex.message})
            raise exception.VolumeBackendAPIException(
                message=('JovianDSS: Failed to create volume %s.',
                         volume['id']))
        ret = {}
        if provider_auth is not None:
            ret['provider_auth'] = provider_auth

        ret['provider_location'] = provider_location

        return ret

    def delete_volume(self, volume):
        """Destroy a volume.

        :param volume: volume reference
        """
        volume_name = volume['id']

        volume_info = {}
        try:
            volume_info = self.ra.get_lun(self.pool, volume_name)
        except exception.JDSSException as err:
            if 'unable to get volume' in err.args[0]:
                LOG.debug('Volume %s does not exist, it seems it was already '
                          'deleted.', volume_name)
                return

        # TODO(andrei.perepiolkin@open-e.com): implement rising of exceptions
        # VolumeIsBusy, VolumeDriverException and VolumeBackendAPIException

        try:
            self.ra.delete_lun(self.pool, volume_name)
        except exception.JDSSRESTException as err:
            if "volume is busy" == err.args[0]:
                LOG.error('Failed to delete volume %(id)', {"id":volume['id']})
                raise exception.VolumeIsBusy(
                    data=('Failed to delete volume %s', volume['id']))
            raise exception.VolumeBackendAPIException(
                "Fail during volume deletion.")

        LOG.debug("JovianDSS: volume info is %s.", volume_info)

        if 'origin' in volume_info and 'replication_driver_data' in volume:

            if (volume_info["origin"] is not None) and\
                    (volume['replication_driver_data'] is not None):

                rdd_data = volume['replication_driver_data']

                rdd_snapshots = self.re_tmp_snapshot.match(rdd_data).group(1)
                origin_volume = jcom.origin_volume(self.pool,
                                                   volume_info["origin"])
                origin_snapshot = jcom.origin_snapshot(volume_info["origin"])
                LOG.debug("JovianDSS: Original vol %(orig_vol)s"
                          "original snap %(orig_snap)s "
                          "replication_driver_data %(rdd)s", {
                              "orig_vol": jcom.origin_volume(
                                  self.pool, volume_info["origin"]),
                              "orig_snap": jcom.origin_snapshot(
                                  volume_info["origin"]),
                              "rdd": rdd_snapshots})

                if origin_snapshot == rdd_snapshots:
                    try:

                        self.ra.delete_snapshot(
                            self.pool,
                            origin_volume,
                            origin_snapshot)

                    except exception.JDSSRESTException as err:
                        LOG.debug(
                            "Unable to delete temporal snapshot %(snapshot)s"
                            " of volume %(volume) with error %(err).", {
                                "snapshot": origin_snapshot,
                                "volume": volume,
                                "err": err})
                        raise exception.SnapshotIsBusy(err)
                    return
        return

    def extend_volume(self, volume, new_size):
        """Extend an existing volume.

        :param volume: volume reference
        :param new_size: volume new size in GB
        """
        LOG.debug("JovianDSS: Extend volume %s", volume['id'])

        try:
            self.ra.extend_lun(self.pool,
                               volume['id'],
                               new_size * o_units.Gi)
        except exception.JDSSException:
            raise exception.VolumeBackendAPIException(
                message=('Failed to extend volume %s.', volume['id']))

    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume.

        :param volume: new volume reference
        :param src_vref: source volume reference
        """
        volume_name = volume['id']
        src_vref_name = src_vref['id']
        tmp_snapshot_name = "tmp_snapshot_for_volume_" + volume_name

        LOG.debug('JovianDSS: create cloned volume %(id)s'
                  'from volume %(id_from)s by tmp snapshot %(snapshot)s.', {
                      "id": volume['id'],
                      "id_from": src_vref_name,
                      "snapshot": tmp_snapshot_name})

        try:
            self.ra.create_snapshot(self.pool, src_vref_name,
                                    tmp_snapshot_name)

        except exception.JDSSException:

            LOG.debug('JovianDSS: Failed to create tmp snapshot %(snapshot)s'
                      'for volume %(volume)s.', {
                          'snapshot': tmp_snapshot_name,
                          'volume': tmp_snapshot_name})

            raise exception.VolumeBackendAPIException(
                'Failed to create tmp snapshot %(snapshot) for volume'
                '%(volume)', {
                    'snapshot': tmp_snapshot_name,
                    'volume': tmp_snapshot_name})

        try:
            self.ra.create_volume_from_snapshot(
                self.pool,
                volume_name,
                tmp_snapshot_name,
                src_vref_name,
                sparse=self.jovian_sparse)

        except exception.JDSSException as err:
            if 'unable to create volume' in err.args[0]:
                LOG.error('Failed to create volume %(vname).', {'vname':volume_name})
                raise exception.VolumeBackendAPIException(
                    "Unable to create volume.")

        if src_vref['size'] < volume['size']:
            self.extend_volume(volume, int(volume['size']))

        ddata = dict()
        ddata['replication_driver_data'] = 'tmp_snapshot:' +\
                                           tmp_snapshot_name +\
                                           ','
        return ddata

    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot.

        If volume_type extra specs includes 'replication: <is> True'
        the driver needs to create a volume replica (secondary),
        and setup replication between the newly created volume and
        the secondary volume.
        """
        LOG.debug('JovianDSS: create volume %(vol)s from snapshot %(snap)s', {
            'vol': volume['id'],
            'snap': snapshot['name']})

        try:
            self.ra.create_volume_from_snapshot(
                self.pool,
                volume['id'],
                snapshot['id'],
                snapshot['volume_id'],
                sparse=self.jovian_sparse)

        except exception.JDSSException as err:
            if 'unable to create volume' in err.args[0]:

                LOG.debug('JovianDSS: Failed to create volume %(vol)'
                          'from snapshot %(snap)', {
                              'vol': volume['id'],
                              'snap': snapshot['id']})

                raise exception.VolumeBackendAPIException(
                    'Failed to create volume %(vol)s from snapshot %(snap)s', {
                        'vol': volume['id'],
                        'snap': snapshot['id']})

        if snapshot['volume_size'] < volume['size']:
            self.extend_volume(volume, int(volume['size']))

    def create_snapshot(self, snapshot):
        """Create snapshot of existing volume.

        :param snapshot: snapshot reference
        """
        LOG.debug('JovianDSS: create snapshot %(snap) for volume %(vol)', {
            'snap': snapshot['id'],
            'vol': snapshot['volume_id']})

        try:
            self.ra.create_snapshot(
                self.pool,
                snapshot['volume_id'],
                snapshot['id'])

        except exception.JDSSRESTException as err:
            LOG.error(('JovianDSS: Failed to create snapshot %(snap)'
                       'for volume %(vol) %(msg).') % {
                           'snap': snapshot['id'],
                           'vol': snapshot['volume_id'],
                           'msg': err.message})

            raise exception.VolumeBackendAPIException(msg)

    def delete_snapshot(self, snapshot):
        """Delete snapshot of existing volume.

        :param snapshot: snapshot reference
        """
        try:
            self.ra.delete_snapshot(
                self.pool,
                snapshot['volume_id'],
                snapshot['id'])

        except exception.JDSSRESTException as err:

            msg = _('Failed to delete snapshot %(snap) for volume %(vol)'
                    'because of %(err).') % {
                        'snap': snapshot['id'],
                        'vol': snapshot['volume_id'],
                        'err': err.message}

            LOG.debug(msg)

            raise exception.VolumeBackendAPIException(msg)

    def local_path(self, volume):
        """Return local path to existing local volume.

        We never have local volumes, so it raises NotImplementedError.

        :raise: :py:exc:`NotImplementedError`
        """
        raise NotImplementedError

    def _get_provider_auth(self):
        """Get provider authentication for the volume.

        :return: string of auth method and credentials
        """
        if not self.jovian_chap_auth:
            return None

        field = string.lowercase + string.uppercase + string.digits
        chap_password = ''.join(random.sample(field,
                                              int(self.jovian_chap_pass_len)))

        if self.jovian_chap_username is not None:
            return '%(auth)s %(user)s %(pass)s' % {
                'auth': 'CHAP',
                'user': self.jovian_chap_username,
                'pass': chap_password
            }

        return None

    def _get_provider_location(self, volume_name):
        """Return volume iscsiadm-formatted provider location string."""
        return '%(host)s:%(port)s,1 %(name)s 0' % {
            'host': self.jovian_host,
            'port': self.jovian_iscsi_target_portal_port,
            'name': self._get_target_name(volume_name)
        }

    def create_export(self, _ctx, volume, connector):
        """Create new export for zvol.

        :param volume: reference of volume to be exported
        :return: iscsiadm-formatted provider location string
        """
        LOG.debug("JovianDSS: create_export for volume: %s.", volume["id"])

        self._prepare_target_volume(volume, connector)

        return {'provider_location': self._get_provider_location(volume['id'])}

    def ensure_export(self, _ctx, volume):
        """Recreate parts of export if necessary.

        :param volume: reference of volume to be exported
        """
        LOG.debug("JovianDSS: ensure_export for volume: %s.", volume['id'])
        self._prepare_target_volume(volume, None)

        return {'provider_location': self._get_provider_location(volume)}

    def remove_export(self, _ctx, volume):
        """Destroy all resources created to export zvol.

        :param volume: reference of volume to be unexported
        """
        LOG.debug("JovianDSS: remove_export for volume: %s.", volume['id'])

        self._remove_target_volume(volume)

        return

    def get_volume_stats(self, refresh=False):
        """Get volume stats.

        If 'refresh' is True, run update the stats first.
        """
        if refresh:
            self._update_volume_stats()

        return self._stats

    def _update_volume_stats(self):
        """Retrieve stats info."""
        LOG.debug('Updating volume stats')
        self._stats = None

        pool_stats = self.ra.get_pool_stats(self.pool)
        total_capacity = math.floor(int(pool_stats["size"]) / o_units.Gi)
        free_capacity = math.floor(int(pool_stats["available"]) / o_units.Gi)

        reserved_percentage = (
            self.configuration.safe_get('reserved_percentage'))

        if total_capacity is None:
            total_capacity = 'unknown'
        if free_capacity is None:
            free_capacity = 'unknown'

        location_info = '%(driver)s:%(host)s:%(volume)s' % {
            'driver': self.__class__.__name__,
            'host': self.jovian_host,
            'volume': self.pool
        }

        self._stats = {
            'vendor_name': 'Open-E',
            'driver_version': self.VERSION,
            'storage_protocol': 'iSCSI',
            'total_capacity_gb': total_capacity,
            'free_capacity_gb': free_capacity,
            'reserved_percentage': int(reserved_percentage),
            'volume_backend_name': self.backend_name,
            'QoS_support': False,
            'location_info': location_info
        }

        LOG.debug('JovianDSS: Total capacity: %d,'
                  'Free %d.',
                  self._stats['total_capacity_gb'],
                  self._stats['free_capacity_gb'])

    def _volume_exists(self, volume_id):
        """Return True if specified volume exists.

        :param volume_id:
        :return:
        """
        return self.ra.is_lun(self.pool, volume_id)

    def _create_new_target_volume(self, volume, target_name, connector=None):
        """_create_new_target_volume.

        Creates new target with user properties for CHAP auth if specified,
        attaches specified volume to it.

        :param volume: volume
        :param target_name: name of new target
        :param connector: connector description
        :return:
        """
        LOG.debug("JovianDSS: Create new target volume.")

        auth = volume['provider_auth']

        chap_cred = dict()
        use_chap = False

        if auth is not None:
            (auth_method, auth_username, auth_secret) = auth.split()
            chap_cred = {"name": auth_username,
                         "password": auth_secret}
            use_chap = True

        # Deny all connections by default
        deny_ip_list = []
        try:
            self.ra.create_target(self.pool,
                                  target_name,
                                  use_chap=use_chap,
                                  deny_ip=deny_ip_list)

        except exception.JDSSRESTException as ex:

            err_msg = ('JovianDSS: Unable to create target %(target)s '
                       'because of %(error)s.' %
                       {'target': target_name, 'error': ex.message})

            LOG.debug(err_msg, resource=volume)

            raise exception.VolumeBackendAPIException(data=err_msg)

        if use_chap:

            try:
                self.ra.create_target_user(self.pool, target_name,
                                           chap_cred)

            except exception.JDSSRESTException as ex:

                err_msg = (_('JovianDSS: Unable to create'
                             ' user %(user)s for target %(target)s'
                             ' because of %(error)s.') %
                           {
                               'target': target_name,
                               'user': chap_cred['name'],
                               'error': six.text_type(ex)})

                LOG.debug(err_msg, resource=volume)

                raise exception.VolumeBackendAPIException(data=err_msg)

        try:
            self.ra.attach_target_vol(
                self.pool,
                target_name,
                volume["id"])

        except exception.JDSSRESTException as ex:

                err_msg = ('JovianDSS: Unable to attach'
                           'target %(target)s to'
                           'volume %(volume)s '
                           'because of %(error)s.' %
                           {'target': target_name,
                            'volume': volume['id'],
                            'error': six.text_type(ex)})

                LOG.debug(err_msg, resource=volume)

                raise exception.VolumeBackendAPIException(data=err_msg)

    def _prepare_target_volume(self, volume, connector):
        """_prepare_target_volume.

        Makes sure that specified volume is connected to appropriate target.
        Creates new target and attaches volume to it if necessary.
        :param volume:
        :param connector:
        :return:
        """
        LOG.debug("JovianDSS: Prepare target volume %s.", volume['id'])

        target_name = self.jovian_target_prefix + volume["id"]

        if self.ra.is_target(self.pool, target_name) is True:
            LOG.debug("JovianDSS: Target %s exists.", target_name)
            if self.ra.is_target_lun(self.pool,
                                     target_name,
                                     volume["id"])\
                    is True:
                return
            else:
                if self.ra.attach_target_vol(
                        self.pool,
                        target_name,
                        volume["id"]) is False:

                    msg = _('Unable to attach volume %(vol)s to'
                            ' target %(targ)s') % {
                                'vol': volume[id],
                                'targ': target_name}
                    LOG.debug(msg)

                    raise exception.VolumeBackendAPIException(
                        message=msg)

        else:
            self._create_new_target_volume(volume, target_name)

        return

    def _remove_target_volume(self, volume):
        """_remove_target_volume

        Ensure that volume is not attached to target and target do not exists.
        :param volume:
        :return:
        """
        target_name = self.jovian_target_prefix + volume['id']
        LOG.debug("JovianDSS: Remove_export.")
        LOG.debug("JovianDSS: detach volume:%(vol)s from target:%(targ)s.", {
            'vol': volume,
            'targ': target_name})

        try:
            self.ra.detach_target_vol(self.pool,
                                      target_name,
                                      volume['id'])
        except exception.JDSSRESTException as ex:
            LOG.debug('Failed to Terminate_connection for target %(targ)s'
                      'because of: %(err)s', {
                          'targ': target_name,
                          'err': str(ex.args[0])})
        except exception.JDSSRESTResourceNotFoundException as ex:
            LOG.debug('Failed to remove resource %(targ) because of %(err).', {
                'targ': target_name,
                'err': str(ex.args[0])})

        LOG.debug("JovianDSS: Delete target: %s.", target_name)

        try:
            self.ra.delete_target(self.pool, target_name)
        except exception.JDSSRESTException as ex:
            LOG.debug('Failed to Terminate_connection for target %(targ)s'
                      'because of: %(err)s', {
                          'targ': target_name,
                          'err': str(ex.args[0])})

        except exception.JDSSRESTResourceNotFoundException as ex:
            LOG.debug('Failed to remove resource %(targ) because of %(err).', {
                'targ': target_name,
                'err': str(ex.args[0])})
        return

    def _get_iscsi_properties(self, volume, connector):
        """Return dict according to cinder/driver.py implementation.

        :param volume:
        :return:
        """
        vname = volume["id"]

        zvol_info = self.ra.get_zvol_info(self.pool, vname)
        if zvol_info is None:
            LOG.debug('JovianDSS: Unable to get zvol lun for'
                      ' volume %s.', vname)

            raise exception.VolumeBackendAPIException(
                'JovianDSS: Unable to get'
                ' zvolume lun for volume %s.', vname)

        iface_info = []
        multipath = connector.get('multipath', False)
        if multipath is True:
            iface_info = self._get_active_ifaces()
            if not iface_info:
                raise exception.InvalidConfigurationValue(
                    'JovianDSS: No available interfaces '
                    'or config excludes them')

        iscsi_properties = dict()

        if multipath:
            iscsi_properties['target_iqns'] = []
            iscsi_properties['target_portals'] = []
            iscsi_properties['target_luns'] = []
            LOG.debug('JovianDSS: tpaths %s.', str(iface_info))
            for iface in iface_info:
                iscsi_properties['target_iqns'].append(
                    self.jovian_target_prefix +
                    vname)
                iscsi_properties['target_portals'].append(
                    iface +
                    ":" +
                    self.jovian_iscsi_target_portal_port)
                iscsi_properties['target_luns'].append(int(zvol_info["lun"]))
        else:
            iscsi_properties['target_iqn'] = self.jovian_target_prefix + vname
            iscsi_properties['target_portal'] = \
                self.jovian_host + ":" + self.jovian_iscsi_target_portal_port

        iscsi_properties['target_discovered'] = False

        auth = volume['provider_auth']
        if auth:
            (auth_method, auth_username, auth_secret) = auth.split()

            iscsi_properties['auth_method'] = auth_method
            iscsi_properties['auth_username'] = auth_username
            iscsi_properties['auth_password'] = auth_secret

        iscsi_properties['target_lun'] = int(zvol_info["lun"])
        return iscsi_properties

    def initialize_connection(self, volume, connector):
        """Initialize the connection and returns connection info.

        The iscsi driver returns a driver_volume_type of 'iscsi'.
        the format of the driver data is defined in smis_get_iscsi_properties.
        Example return value:
        .. code-block:: json
            {
                'driver_volume_type': 'iscsi'
                'data': {
                    'target_discovered': True,
                    'target_iqn': 'iqn.2010-10.org.openstack:volume-00000001',
                    'target_portal': '127.0.0.0.1:3260',
                    'volume_id': '12345678-1234-4321-1234-123456789012',
                }
            }
        """
        iscsi_properties = self._get_iscsi_properties(volume, connector)

        target_name = self.jovian_target_prefix + volume["id"]

        LOG.debug("JovianDSS: "
                  "providing connection info %s", str(iscsi_properties))
        return {
            'driver_volume_type': 'iscsi',
            'data': iscsi_properties,
        }

    def terminate_connection(self, volume, connector, force=False, **kwargs):
        """terminate_connection

        Disallow connection from connector by removing it's ip
        from allowed ip list.
        """

        return

    def attach_volume(self,
                      context,
                      volume,
                      instance_uuid,
                      host_name,
                      mount_point):
        """Callback for volume attached to instance or host."""
        LOG.debug("JovianDSS: Attach volume:"
                  " context: %(context)s,"
                  " volume: %(volume)s,"
                  " instance_uuid: %(uuid)s,"
                  " host_name: %(host)s,"
                  " mount point: %(mount)s.", {
                      'context': context,
                      'volume': volume,
                      'uuid': instance_uuid,
                      'host': host_name,
                      'mount': mount_point})

    def detach_volume(self,
                      context,
                      volume,
                      attachment=None):
        """Callback for volume detached."""
        LOG.debug("JovianDSS: Detach volume:"
                  " context: %(context), volume: %(vol).", {
                      'context': context,
                      'vol': volume})

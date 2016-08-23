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


from oslo_log import log as logging
import oslo_utils
from oslo_utils import netutils as o_netutils
from oslo_utils import units as o_units

from cinder import exception
from cinder.volume import driver
from cinder.volume.drivers import joviandss
from cinder.volume.drivers.joviandss import options
from cinder.volume.drivers.joviandss import rest
from cinder.volume.drivers.joviandss import common as jcom

import math
import re
import random
import string
import six


VERSION = '1.0.0'
LOG = logging.getLogger(__name__)


class JovianISCSIDriver(driver.ISCSIDriver):
    """Executes volume driver commands on Open-E JovianDSS V7.
    """

    def __init__(self, *args, **kwargs):
        super(JovianISCSIDriver, self).__init__(*args, **kwargs)
        self.ra = None
        self.db = kwargs.get('db')
        self.comm = None

        LOG.debug('JovianDSS: Enter JovianISCSIDriver')
        self.configuration.append_config_values(
            options.JDSS_CONNECTION_OPTIONS)
        self.configuration.append_config_values(
            options.JDSS_ISCSI_OPTIONS)
        self.configuration.append_config_values(
            options.JDSS_VOLUME_OPTIONS)
        self.pool = self.configuration.safe_get('jovian_pool')

        self.jovian_target_prefix = self.configuration.safe_get(
            'jovian_target_prefix')

        self.jovian_target_group_prefix = self.configuration.safe_get(
            'jovian_target_group_prefix')

        self.jovian_host = self.configuration.safe_get('jovian_host')

        if o_netutils.is_valid_ip(self.jovian_host) is False:
            err_msg = (_('JovianDSS: Invalid value of jovian_host property:'
                         '%(addr)s, IP address expected.') %
                       {'addr': self.jovian_host})

            LOG.error(err_msg)
            raise exception.InvalidConfigurationValue(err_msg)

        self.jovian_iscsi_target_portal_port = str(
            self.configuration.safe_get('jovian_iscsi_target_portal_port'))

        pass

    @property
    def backend_name(self):
        backend_name = None
        if self.configuration:
            backend_name = self.configuration.safe_get('volume_backend_name')
        if not backend_name:
            backend_name = self.__class__.__name__
        return backend_name

    def do_setup(self, context):
        self.re_tmp_snapshot = re.compile(r'tmp_snapshot:(.+),')

        self.comm = jcom.JDSSCommon(self.configuration, self, context, self.db)
        self.ra = rest.JovianRESTAPI(self.configuration)



        pass

    def check_for_setup_error(self):
        """Verify that the pool exists.
        """
        if not self.ra.is_pool_exists(self.pool):
            LOG.error(
                "JovianDSS:  Pool %s does not exist in JovianDSS", self.pool)
            raise exception.VolumeDriverException("Bad configuration expected.")
    # TODO: Provide additional checks

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

    def create_volume(self, volume):
        """Create a volume.

        :param volume: volume reference
        :return: model update dict for volume reference
        """

        vname = jcom.cinder_name_2_id(volume['name'])
        LOG.debug('JovianDSS: Creating volume {}.'.format(volume['name']))
        
        provider_location = self._get_provider_location(vname)
        provider_auth = self._get_provider_auth()

        try:
            self.ra.create_lun(self.pool, vname, volume['size'])

        except jcom.JDSSRESTException as ex:
            LOG.error(
                'JovianDSS: Failed to create volume {} because of {}.'.format(
                    volume['name'], ex))
            raise exception.VolumeBackendAPIException(
                message=('JovianDSS: Failed to create volume {}.'.format(
                    volume['name'])))

        return {'provider_location': provider_location,
                'provider_auth': provider_auth}

    def delete_volume(self, volume):
        """Destroy a volume.

        :param volume: volume reference
        """
        volume_name = jcom.cinder_name_2_id(volume['name'])
        # TODO: remove this logs

        LOG.debug('JovianDSS: Delete volume {}.'.format(volume['name']))

        volume_info = {}
        try:
            volume_info = self.ra.get_lun(self.pool, volume_name)
        except joviandss.JDSSException as exept:
            if 'unable to get volume' in exept.args[0]:
                LOG.info('Volume {} does not exist, it seems it was already '
                         'deleted.'.format(volume_name))
                return

        #TODO: implement rising of exceptions
        #cinder.exception.VolumeIsBusy
        #cinder.exception.VolumeDriverException
        #cinder.exception.VolumeBackendAPIException

        try:
            self.ra.delete_lun(self.pool, volume_name)
        except jcom.JDSSRESTException as exept:
            if "volume is busy" == exept.args[0]:
                LOG.error('Failed to delete volume {}.'.format(volume['name']))
                raise exception.VolumeIsBusy(
                    data=('Failed to delete volume {}.'.format(volume['name'])))
            raise exception.VolumeBackendAPIException(
                "Fail during volume delition.")

        LOG.debug("JovianDSS: volumeinfo is {}".format(volume_info))

        if 'origin' in volume_info and 'replication_driver_data' in volume:

            if (volume_info["origin"] is not None) and\
                    (volume['replication_driver_data'] is not None):

                rdd_data = volume['replication_driver_data']

                rdd_snapshots = self.re_tmp_snapshot.match(rdd_data).group(1)
                origin_volume = jcom.origin_volume(self.pool,
                                                   volume_info["origin"])
                origin_snapshot = jcom.origin_snapshot( volume_info["origin"])
                LOG.debug("JovianDSS: Original vol {}  original snap {}\
                 replication_driver_data {}".format( \
                    jcom.origin_volume(self.pool, volume_info["origin"]),
                    jcom.origin_snapshot( volume_info["origin"]),
                    rdd_snapshots))

                if origin_snapshot == rdd_snapshots:
                    try:

                        self.comm.delete_snapshot(
                            self.pool,
                            origin_volume,
                            origin_snapshot)

                    except exception.SnapshotIsBusy as exept:
                        LOG.error(
                            "Unable to delete temporal snapshot {1}\
                             of volume {2} with error {3}.".format(
                                origin_snapshot, origin_volume), exept)
                    return
        return

    def extend_volume(self, volume, new_size):
        """Extend an existing volume.

        :param volume: volume reference
        :param new_size: volume new size in GB
        """

        LOG.debug("JovianDSS: Extend volume {}".format(volume))        
        
        try:
            self.ra.extend_lun(self.pool,
                               jcom.cinder_name_2_id(volume['name']),
                               new_size)
        except:
            LOG.error('Failed to extend volume {}.'.format(volume['name']))
            raise exception.VolumeBackendAPIException(
                message=('Failed to extend volume {}.'.format(volume['name'])))

    def create_cloned_volume(self, volume, src_vref):
        """Creates a clone of the specified volume.

        :param volume: new volume reference
        :param src_vref: source volume reference
        """
        volume_name = jcom.cinder_name_2_id(volume['name'])
        src_vref_name = jcom.cinder_name_2_id(src_vref['name'])
        tmp_snapshot_name = "tmp_snapshot_for_volume_" + volume_name

        LOG.debug('JovianDSS: create cloned volume {} \
         from volume {} by tmp snapshot {}.'.format(
            volume['name'],
            src_vref['name'],
            tmp_snapshot_name))

        try:
            self.ra.create_snapshot(self.pool, src_vref_name, tmp_snapshot_name)

        except:

            LOG.error('JovianDSS: Failed to create tmp snapshot {} \
             for volume {}.'.format(tmp_snapshot_name, tmp_snapshot_name))

            raise exception.VolumeBackendAPIException(
                'Failed to create tmp snapshot {} for volume {}.'.format(
                    tmp_snapshot_name,
                    tmp_snapshot_name))

        try:
            self.ra.create_volume_from_snapshot(
                self.pool,
                volume_name,
                tmp_snapshot_name,
                src_vref_name)

        except joviandss.JDSSException as exept:
            if 'unable to create volume' in exept.args[0]:
                LOG.error('Failed to create volume {}.'.format(volume_name))
                raise exception.VolumeBackendAPIException(
                    "Unable to create volume.")

        ddata = dict()
        ddata['replication_driver_data'] = 'tmp_snapshot:' +\
                                           tmp_snapshot_name +\
                                           ','
        return ddata

    def create_volume_from_snapshot(self, volume, snapshot):
        """Creates a volume from a snapshot.

        If volume_type extra specs includes 'replication: <is> True'
        the driver needs to create a volume replica (secondary),
        and setup replication between the newly created volume and
        the secondary volume.
        """

        LOG.debug('JovianDSS: create volume {} from snapshot {}'.format(
            volume['name'], snapshot['name']))

        try:
            self.ra.create_volume_from_snapshot(
                self.pool,
                jcom.cinder_name_2_id(volume['name']),
                snapshot['name'],
                jcom.cinder_name_2_id(snapshot['volume_name']))

        except joviandss.JDSSException as exept:
            if 'unable to create volume' in exept.args[0]:

                LOG.error('Failed to create volume {} from snapshot {}.'.format(
                    volume['name'],
                    snapshot['name']))

                raise exception.VolumeBackendAPIException(
                    'Failed to to create volume {} from snapshot {}.'.format(
                        volume['name'],
                        snapshot['name']))

    def create_snapshot(self, snapshot):
        """Create snapshot of existing volume.

        :param snapshot: snapshot reference
        """

        LOG.debug('JovianDSS: create snapshot {} for volume {}'.format(
            snapshot['name'],
            snapshot['volume_name']))

        try:
            self.ra.create_snapshot(
                self.pool,
                jcom.cinder_name_2_id(snapshot['volume_name']),
                snapshot['name'])

        except:
            LOG.error('Failed to create snapshot {} for volume {}.'.format(
                snapshot['name'],
                snapshot['volume_name']))

            raise exception.VolumeBackendAPIException(
                'Failed to create snapshot {} for volume {}.'.format(
                    snapshot['name'],
                    snapshot['volume_name']))

    def delete_snapshot(self, snapshot):
        """Delete snapshot of existing volume.

        :param snapshot: snapshot reference
        """
        try:
            self.comm.delete_snapshot(
                self.pool,
                jcom.cinder_name_2_id(snapshot['volume_name']),
                snapshot['name'])

        except:

            LOG.error('Failed to delete snapshot {} for volume {}.'.format(
                snapshot['name'],
                snapshot['volume_name']))

            raise exception.VolumeBackendAPIException(
                'Failed to delete snapshot {} for volume {}.'.format(
                    snapshot['name'],
                    snapshot['volume_name']))

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

        chap_auth = self.configuration.safe_get('jovian_chap_auth')

        if not chap_auth:
            return None

        chap_username = self.configuration.safe_get('jovian_chap_username')
        password_len = self.configuration.safe_get('jovian_chap_pass_len')

        field = string.lowercase + string.uppercase + string.digits
        chap_password = ''.join(random.sample(field, int(password_len)))

        if chap_username is not None:
            return '%(auth)s %(user)s %(pass)s' % {
                'auth': 'CHAP',
                'user': chap_username,
                'pass': chap_password
                }

        return None

    def _get_provider_location(self, volume_name):
        """Returns volume iscsiadm-formatted provider location string."""
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
        LOG.debug("JovianDSS: create_export for volume: {}".format(
            volume["name"]))

        self._prepare_target_volume(volume, connector)

        return {'provider_location': self._get_provider_location(volume)}

    def ensure_export(self, _ctx, volume):
        """Recreate parts of export if necessary.

        :param volume: reference of volume to be exported
        """
        LOG.debug("JovianDSS: ensure_export for volume: {}".format(
            volume["name"]))
        self._prepare_target_volume(volume, None)

        return {'provider_location': self._get_provider_location(volume)}

    def remove_export(self, _ctx, volume):
        """Destroy all resources created to export zvol.

        :param volume: reference of volume to be unexported
        """
        LOG.debug("JovianDSS: remove_export for volume: {}".format(
            volume["name"]))

        target_name = jcom.get_jprefix() + jcom.cinder_name_2_id(volume["name"])
        LOG.debug("JovianDSS: Remove_export.")
        LOG.debug("JovianDSS: detach volume:{} from target:{},".format(
            volume,
            target_name))

        try:
            self.ra.detach_target_vol(self.pool,
                                      target_name,
                                      jcom.cinder_name_2_id(volume["name"]))
        except jcom.JDSSRESTException as ex:
            LOG.error('Failed to Terminate_connection for TARGET {} {}.'.format(
                target_name,
                str(ex.args[0])))
        except jcom.JDSSRESTResourceNotFoundException as ex:
            LOG.error('Failed to remove resource {} because {}.'.format(
                target_name,
                str(ex.args[0])))

        LOG.debug("JovianDSS: Delete target:{}".format(target_name))

        try:
            self.ra.delete_target(self.pool, target_name)
        except jcom.JDSSRESTException as ex:
            LOG.error('Failed to Terminate_connection for TARGET {} {}.'.format(
                target_name,
                str(ex.args[0])))
        except jcom.JDSSRESTResourceNotFoundException as ex:
            LOG.error('Failed to remove resource {} because {}.'.format(
                target_name,
                str(ex.args[0])))

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
            'reserved_percentage': 0,
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
        """Creates new target with user properties for CHAP auth if specified,
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

        LOG.debug("JovianDSS: Provider auth is : {}.".format(auth))

        if auth is not None:
            (auth_method, auth_username, auth_secret) = auth.split()
            chap_cred = {"name": auth_username,
                         "password": auth_secret}
            use_chap = True

        try:
            self.ra.create_target(self.pool, target_name, use_chap=use_chap)

        except jcom.JDSSRESTException as ex:

            err_msg = (_('JovianDSS: Unable to create '
                         'target %(target)s '
                         'because of %{error}s.') %
                       {'target': target_name,
                        'error': six.text_type(ex)})

            LOG.error(err_msg, resource=volume)

            raise exception.VolumeBackendAPIException(data=err_msg)

        if use_chap:

            try:
                self.ra.create_target_user(self.pool, target_name,
                                           chap_cred)

            except jcom.JDSSRESTException as ex:

                err_msg = (_('JovianDSS: Unable to create'
                             ' user %{user}s for target %{target}s'
                             ' because of %{error}s.') %
                           {
                               'target': target_name,
                               'user': chap_cred['name'],
                               'error': six.text_type(ex)})

                LOG.error(err_msg, resource=volume)

                raise exception.VolumeBackendAPIException(data=err_msg)

        try:
            self.ra.attach_target_vol(
                self.pool,
                target_name,
                jcom.cinder_name_2_id(volume["name"]))

        except jcom.JDSSRESTException as ex:

                err_msg = (_('JovianDSS: Unable to attach'
                                'target %(target)s to'
                                'volume %(volume)s '
                                'because of %{error}s.') %
                {'target': target_name,
                 'volume': volume["name"],
                 'error': six.text_type(ex)})

                LOG.error(err_msg, resource=volume)

                raise exception.VolumeBackendAPIException(data=err_msg)

    def _prepare_target_volume(self, volume, connector):
        """Makes sure that specified volume is connected to appropriate target.
        Creates new target and attaches volume to it if necessary.

        :param volume:
        :param connector:
        :return:
        """

        LOG.debug("JovianDSS: Prepare target volume.{}".format(connector))

        target_name = jcom.get_jprefix() + jcom.cinder_name_2_id(volume["name"])

        if self.ra.is_target(self.pool, target_name) is True:
            LOG.debug("JovianDSS: Target exists.")
            if self.ra.is_target_lun(self.pool,
                                     target_name,
                                     jcom.cinder_name_2_id(volume["name"]))\
                    is True:
                return
            else:
                if self.ra.attach_target_vol(
                        self.pool,
                        target_name,
                        jcom.cinder_name_2_id(volume["name"]))\
                        is False:

                    LOG.error('Unable to attach volume {} to target {}.'.format(
                        volume, target_name))
                    raise exception.VolumeBackendAPIException(
                        message=('Unable to volume {} to target {}.'.format(
                            jcom.cinder_name_2_id(volume["name"]),
                            target_name)))
        else:

            self._create_new_target_volume(volume, target_name)

    def _get_iscsi_properties(self, volume):
        """Returns dict according to cinder/driver.py implementation

        :param volume:
        :return:
        """

        vname = jcom.cinder_name_2_id(volume["name"])

        zvol_info = self.ra.get_zvol_info(self.pool, vname)
        if zvol_info is None:
            LOG.error('JovianDSS: Unable to get zvol lun for'
                      ' volume {}.'.format(vname))

            raise exception.VolumeBackendAPIException(
                'JovianDSS: Unable to get'
                ' zvolume lun for volume {}.'.format(vname))

        iscsi_properties = dict()
        iscsi_properties['target_discovered'] = False
        iscsi_properties['target_iqn'] = jcom.get_jprefix() + vname
        iscsi_properties['target_portal'] = \
            self.jovian_host + ":" + self.jovian_iscsi_target_portal_port

        auth = volume['provider_auth']
        if auth:
            (auth_method, auth_username, auth_secret) = auth.split()

            iscsi_properties['auth_method'] = auth_method
            iscsi_properties['auth_username'] = auth_username
            iscsi_properties['auth_password'] = auth_secret

        iscsi_properties['target_lun'] = int(zvol_info["lun"])
        return iscsi_properties

    def initialize_connection(self, volume, connector):
        """Initializes the connection and returns connection info.

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
        iscsi_properties = self._get_iscsi_properties(volume)

        LOG.info("JovianDSS: "
                 "providing connection info {}".format(iscsi_properties))
        return {
            'driver_volume_type': 'iscsi',
            'data': iscsi_properties,
            'status' : "in-use"
        }

    def terminate_connection(self, volume, connector, force=False, **kwargs):
        return {
            'status' : "available"
        }

    def attach_volume(self,
                      context,
                      volume,
                      instance_uuid,
                      host_name,
                      mount_point):

        LOG.debug("JovianDSS: Attach volume:"
                  " context:{},"
                  " volume:{},"
                  " instance_uuid: {},"
                  " host_name: {},"
                  " mount point: {}.".format(
                    context,
                    volume,
                    instance_uuid,
                    host_name,
                    mount_point))
        pass

    def detach_volume(self,
                      context,
                      volume,
                      attachment=None):

        """Callback for volume detached."""
        LOG.debug( "JovianDSS: Detach volume:"
                   " context:{}, volume:{}".format(context, volume))
        pass


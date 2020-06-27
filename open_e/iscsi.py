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

import six
from oslo_log import log as logging
from oslo_utils import units as o_units

from cinder import exception
from cinder.i18n import _
from cinder.volume import driver
from cinder.volume.drivers.open_e.jovian_common import exception as jexc
from cinder.volume.drivers.open_e.jovian_common import jdss_common as jcom
from cinder.volume.drivers.open_e.jovian_common import rest
from cinder.volume.drivers.open_e import options


LOG = logging.getLogger(__name__)


class JovianISCSIDriver(driver.ISCSIDriver):
    """Executes volume driver commands on Open-E JovianDSS V7.

    Version history:

    .. code-block:: none

        1.0.0 - Initial base driver
        1.0.1 - Provide support for multiple target IP
        1.0.2 - Provide support for HA claster
                        support for cascade deletion
    """

    # ThirdPartySystems wiki page
    CI_WIKI_NAME = "Open-E_JovianDSS_CI"
    VERSION = "1.0.2"

    def __init__(self, *args, **kwargs):
        super(JovianISCSIDriver, self).__init__(*args, **kwargs)

        self.ra = None
        self.conf = dict()

        self.configuration.append_config_values(
            options.jdss_connection_opts)
        self.configuration.append_config_values(
            options.jdss_iscsi_opts)
        self.configuration.append_config_values(
            options.jdss_volume_opts)

        self._stats = None

        self._pool = 'Pool-0'
        self.jovian_iscsi_target_portal_port = "3260"

        self.jovian_target_prefix = 'iqn.2020-04.com.open-e.cinder:'

        self.jovian_chap_pass_len = 12
        self.jovian_sparse = False
        self.jovian_ignore_tpath = None
        self.jovian_hosts = None
        self.ra = None

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
        self._pool = self.configuration.safe_get('jovian_pool')
        self.jovian_iscsi_target_portal_port = self.configuration.safe_get(
            'jovian_iscsi_target_portal_port')

        self.jovian_target_prefix = self.configuration.safe_get(
            'jovian_target_prefix')

        self.jovian_chap_pass_len = self.configuration.safe_get(
            'jovian_chap_pass_len')
        self.jovian_sparse = (
            self.configuration.safe_get('jovian_provisioning_thin'))
        self.jovian_ignore_tpath = self.configuration.get(
            'jovian_ignore_tpath', None)
        self.jovian_hosts = self.configuration.safe_get(
            'jovian_hosts')
        self.ra = rest.JovianRESTAPI(self.configuration)

    def check_for_setup_error(self):
        """Verify that the pool exists."""
        if len(self.jovian_hosts) == 0:
            msg = _("No hosts provided in configuration")
            raise exception.VolumeDriverException(msg)

        if not self.ra.is_pool_exists():
            msg = (_("Unable to identify pool %s") % self._pool)
            raise exception.VolumeDriverException(msg)

    def _get_target_name(self, volume_name):
        """Return iSCSI target name to access volume."""
        return '%s%s' % (self.jovian_target_prefix, volume_name)

    def _get_active_ifaces(self):
        """Return list of ip addreses for iSCSI connection"""

        return self.jovian_hosts

    def create_volume(self, volume):
        """Create a volume.

        :param volume: volume reference
        :return: model update dict for volume reference
        """
        vname = jcom.vname(volume['id'])
        LOG.debug('creating volume %s.', vname)

        provider_location = self._get_provider_location(vname)
        provider_auth = self._get_provider_auth()

        try:
            self.ra.create_lun(vname,
                               volume['size'] * o_units.Gi,
                               sparse=self.jovian_sparse)

        except jexc.JDSSRESTException as ex:
            LOG.error("Create volume error. Because %(err)s",
                      {"err": ex.message})
            raise exception.VolumeBackendAPIException(
                message=(_('Failed to create volume %s.') % volume['id']))
        ret = {}
        if provider_auth is not None:
            ret['provider_auth'] = provider_auth

        ret['provider_location'] = provider_location

        return ret

    def _hide_object(self, vname):
        """Mark volume/snapshot as hidden

        :param vname: physical volume name
        """
        rename = {'name': jcom.hidden(vname)}
        deletable = False
        try:
            self.ra.modify_lun(vname, rename)
        except jexc.JDSSException as err:
            LOG.warning('Failure in hidding  %s,'
                        ' err: %s', vname, err)
            msg = (_('Failure in interruction with %s.') % vname)
            raise exception.VolumeBackendAPIException(msg)

    def _clean_garbage_snapshots(self, vname, snapshots):
        """Delete physical snapshots that have no descendents"""
        garbage = []
        LOG.debug("clean_garbage_snapshots-----" + str(snapshots))
        for snap in snapshots:
            if snap['clones'] == '':
                try:
                    self.ra.delete_snapshot(vname, snap['name'])
                except jexc.JDSSException as err:
                    args = {'obj': vname, 'err': err.message}
                    msg = (_("Unable to clean garbage for "
                             "%(obj)s: %(err)s") % args)
                    raise exception.VolumeBackendAPIException(msg)
                garbage.append(snap)
        for snap in garbage:
            snapshots.remove(snap)

        return snapshots

    def _cascade_volume_delete(self, o_vname, o_snaps):
        """Delete or hides volume(if it is busy)

        Go over snapshots and deletes them if possible
        Calls for recursiv evolume deletion if volume do not have childs
        """
        vsnaps = []
        deletable = True

        for snap in o_snaps:
            if 's_' in snap['name']:
                vsnaps += [(snap['name'],
                            jcom.full_name_volume(snap['clones']))]

        active_vsnaps = [vs for vs in vsnaps if jcom.is_hidden(vs[1]) is False]

        # If volume have clones or hidden snapshots it should be hidden
        if len(active_vsnaps) < len(o_snaps):
            deletable = False

        for vsnap in active_vsnaps:
            psnap = []
            try:
                psnap = self.ra.get_snapshots(vsnap[1])
                psnap = self._clean_garbage_snapshots(vsnap[1], psnap)
            except jexc.JDSSException as err:
                LOG.warning("Failure in getting phisical snapshots "
                            "for virtual snapshot %s, err: %s", vsnap[1], err)
                msg = (_('Failure in interruction with '
                         'snapshot %s.') % vsnap[1])
                raise exception.VolumeBackendAPIException(msg)
            if len(psnap) > 0:
                deletable = False
                self._hide_object(o_vname)
            else:
                try:
                    self.ra.delete_snapshot(o_vname,
                                            vsnap[0],
                                            recursively_children=True,
                                            recursively_dependents=True,
                                            force_umount=True)
                except jexc.JDSSException as err:
                    LOG.warning('Failure during deletion of physical '
                                'snapshot %s, err: %s', vsnap[0], err)
                    msg = (_('Failure during deletin of virtual snapshot '
                             '%s') % vsnap[1])
                    raise exception.VolumeBackendAPIException(msg)

        if deletable:
            self._gc_delete(o_vname)

    def delete_volume(self, volume, cascade=False):
        """Delete volume

        :param volume: volume reference
        :param cascade: remove snapshots of a volume as well
        """
        vname = jcom.vname(volume['id'])

        LOG.debug('deleating volume %s.', vname)

        snapshots = None
        try:
            snapshots = self.ra.get_snapshots(vname)
        except jexc.JDSSResourceNotFoundException:
            LOG.debug('volume %s dne, it was already'
                      'deleted.', vname)
            return
        except jexc.JDSSException as err:
            raise exception.VolumeBackendAPIException(err.message)

        snapshots = self._clean_garbage_snapshots(vname, snapshots)

        if cascade:
            self._cascade_volume_delete(vname, snapshots)
        else:
            if len(snapshots) > 0:
                self._hide_object(vname)
            else:
                self._gc_delete(vname)

    def _gc_delete(self, vname):
        """Delete volume and its hidden parents

        Deletes volume going recursivly to first active parent and cals
        recursive deletion
        """
        vol = None
        try:
            vol = self.ra.get_lun(vname)
        except jexc.JDSSResourceNotFoundException:
            LOG.debug('Volume %s does not exist, it was already'
                      'deleted.', vname)
            return
        except jexc.JDSSException as err:
            raise exception.VolumeBackendAPIException(err.message)

        if not vol['is_clone']:
            try:
                self.ra.delete_lun(vname)
            except jexc.JDSSRESTException as err:
                LOG.debug(
                    "Unable to delete physical volume %(volume)s "
                    "with error %(err)s.", {
                        "volume": vname,
                        "err": err})
                raise exception.SnapshotIsBusy(err)
        else:
            self._delete_back_recursivly(jcom.origin_volume(vol['origin']),
                                         jcom.origin_snapshot(vol['origin']))

    def _delete_back_recursivly(self, opvname, opsname):
        """Deletes snapshot by removing its oldest removable parent

        Checks if source volume for this snapshot is hidden:
        If it is hidden and have no other descenents, it calls itself on its
            source snapshot if such exists, or deletes it
        If it is not hidden, trigers delete for snapshot

        :param ovname: origin phisical volume name
        :param osname: origin phisical snapshot name
        """

        if jcom.is_hidden(opvname):
            # Resource is hidden
            snaps = []
            try:
                snaps = self.ra.get_snapshots(opvname)
            except jexc.JDSSResourceNotFoundException:
                LOG.debug('Unable to get physical snapshots related to '
                          ' physical volume %s, volume do not exist', opvname)
                return
            except jexc.JDSSException as err:
                raise exception.VolumeBackendAPIException(err.message)

            snaps = self._clean_garbage_snapshots(opvname, snaps)

            if len(snaps) > 1:
                try:
                    self.ra.delete_snapshot(opvname,
                                            opsname,
                                            recursively_children=True,
                                            recursively_dependents=True,
                                            force_umount=True)
                except jexc.JDSSException as err:
                    raise exception.VolumeBackendAPIException(err.message)
            else:
                vol = None
                try:
                    vol = self.ra.get_lun(opvname)

                except jexc.JDSSResourceNotFoundException:
                    LOG.debug('volume %s does not exist, it was already'
                              'deleted.', opvname)
                    return
                except jexc.JDSSException as err:
                    raise exception.VolumeBackendAPIException(err.message)

                if vol['is_clone']:
                    self._delete_back_recursivly(
                        jcom.origin_volume(vol['origin']),
                        jcom.origin_snapshot(vol['origin']))
                else:
                    self.ra.delete_lun(opvname,
                                       recursively_children=True,
                                       recursively_dependents=True,
                                       force_umount=True)
        else:
            # Resource is active
            try:
                self.ra.delete_snapshot(opvname,
                                        opsname,
                                        recursively_children=True,
                                        recursively_dependents=True,
                                        force_umount=True)
            except jexc.JDSSException as err:
                raise exception.VolumeBackendAPIException(err.message)

    def extend_volume(self, volume, new_size):
        """Extend an existing volume.

        :param volume: volume reference
        :param new_size: volume new size in GB
        """
        LOG.debug("Extend volume %s", volume['id'])

        try:
            self.ra.extend_lun(jcom.vname(volume['id']),
                               new_size * o_units.Gi)
        except jexc.JDSSException:
            raise exception.VolumeBackendAPIException(
                message=('Failed to extend volume %s.', volume['id']))

    def _clone_object(self, oname, coname):
        """Creates a clone of specified object

        :param: oname: name of an object to clone
        :param: coname: name of a new clone
        """
        LOG.debug('cloning %(oname)s to %(coname)s', {
            "oname": oname,
            "coname": coname})

        try:
            self.ra.create_snapshot(oname, coname)
        except jexc.JDSSRESTSnapshotExistsException as err:
            try:
                self.ra.delete_snapshot(oname, coname)
            except jexc.JDSSRESTSnapshotIsBusyException as err:
                raise exception.Duplicate()
            except jexc.JDSSException as err:
                LOG.warning(err.message)
                raise exception.VolumeBackendAPIException(
                    (_("Unable to create volume %s.") % coname))

        except jexc.JDSSException as err:
            args = {'snapshot': coname,
                    'object': oname,
                    'err': err.message}
            msg = (_('Failed to create tmp snapshot %(snapshot)s'
                     'for object %(object)s: %(err)s') % args)
            raise exception.VolumeBackendAPIException(message=msg)

        try:
            self.ra.create_volume_from_snapshot(
                coname,
                coname,
                oname,
                sparse=self.jovian_sparse)
        except jexc.JDSSRESTVolumeExistsException as err:
            raise exception.Duplicate()
        except jexc.JDSSException as err:
            try:
                self.ra.delete_snapshot(oname, coname)
            except jexc.JDSSRESTSnapshotIsBusyException as err:
                raise exception.Duplicate()
            except jexc.JDSSException as err:
                LOG.warning(err.message)
                raise exception.VolumeBackendAPIException(
                    (_("Unable to create volume %s.") % coname))

    def create_cloned_volume(self, volume, src_vref):
        """Create a clone of the specified volume.

        :param volume: new volume reference
        :param src_vref: source volume reference
        """
        cvname = jcom.vname(volume['id'])

        vname = jcom.vname(src_vref['id'])

        LOG.debug('cloned volume %(id)s to %(id_clone)s', {
            "id": src_vref['id'],
            "id_clone": volume['id']})

        self._clone_object(vname, cvname)

        self.extend_volume(volume, int(volume['size']))

        provider_location = self._get_provider_location(cvname)
        provider_auth = self._get_provider_auth()

        ret = {}
        if provider_auth is not None:
            ret['provider_auth'] = provider_auth

        ret['provider_location'] = provider_location

        return ret

    def create_volume_from_snapshot(self, volume, snapshot):
        """Create a volume from a snapshot.

        If volume_type extra specs includes 'replication: <is> True'
        the driver needs to create a volume replica (secondary),
        and setup replication between the newly created volume and
        the secondary volume.
        """
        LOG.debug('create volume %(vol)s from snapshot %(snap)s', {
            'vol': volume['id'],
            'snap': snapshot['id']})

        cvname = jcom.vname(volume['id'])
        sname = jcom.sname(snapshot['id'])

        self._clone_object(sname, cvname)

        try:
            self.extend_volume(volume, int(volume['size']))
        except jexc.JDSSException as err:
            # If volume can't be set to a proper size make sure to clean it
            # before failing
            self._delete_back_recursivly(sname, cvname)
            raise exception.VolumeBackendAPIException(err.message)

        provider_location = self._get_provider_location(cvname)
        provider_auth = self._get_provider_auth()

        ret = {}
        if provider_auth is not None:
            ret['provider_auth'] = provider_auth

        ret['provider_location'] = provider_location

        return ret

    def create_snapshot(self, snapshot):
        """Create snapshot of existing volume.

        :param snapshot: snapshot reference
        """
        LOG.debug('create snapshot %(snap)s for volume %(vol)s', {
            'snap': snapshot['id'],
            'vol': snapshot['volume_id']})

        vname = jcom.vname(snapshot['volume_id'])
        sname = jcom.sname(snapshot['id'])

        self._clone_object(vname, sname)

        try:
            self.ra.make_readonly_lun(sname)
        except jexc.JDSSException as err:
            # Name of snapshot should be the same as a name of volume
            # that is going to be created from it
            self._delete_back_recursivly(sname, vname)
            raise exception.VolumeBackendAPIException(err.message)

    def delete_snapshot(self, snapshot):
        """Delete snapshot of existing volume.

        :param snapshot: snapshot reference
        """
        sname = jcom.sname(snapshot['id'])

        LOG.debug('deleating snapshot %s.', sname)

        snapshots = None
        try:
            snapshots = self.ra.get_snapshots(sname)
        except jexc.JDSSResourceNotFoundException:
            LOG.debug('physical volume %s dne, it was already'
                      'deleted.', sname)
            return
        except jexc.JDSSException as err:
            raise exception.VolumeBackendAPIException(err.message)

        snapshots = self._clean_garbage_snapshots(sname, snapshots)

        if len(snapshots) > 0:
            self._hide_object(sname)
        else:
            self._gc_delete(sname)

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
        field = "abcdefghijklmnopqrstuvwxyz"
        field += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        field += "0123456789"

        chap_user = ''.join(random.sample(field, 8))
        chap_password = ''.join(random.sample(field,
                                              int(self.jovian_chap_pass_len)))

        return 'CHAP {user} {passwd}'.format(
            user=chap_user, passwd=chap_password)

    def _get_provider_location(self, volume_name):
        """Return volume iscsiadm-formatted provider location string."""
        return '{host}:{port},1 {name} 0'.format(
            host=self.ra.get_active_host(),
            port=self.jovian_iscsi_target_portal_port,
            name=self._get_target_name(volume_name)
        )

    def create_export(self, _ctx, volume, connector):
        """Create new export for zvol.

        :param volume: reference of volume to be exported
        :return: iscsiadm-formatted provider location string
        """
        LOG.debug("create export for volume: %s.", volume["id"])

        self._create_target_volume(volume, connector)

        return {'provider_location': self._get_provider_location(volume['id'])}

    def ensure_export(self, _ctx, volume):
        """Recreate parts of export if necessary.

        :param volume: reference of volume to be exported
        """
        LOG.debug("ensure export for volume: %s.", volume['id'])
        self._ensure_target_volume(volume)

    def remove_export(self, _ctx, volume):
        """Destroy all resources created to export zvol.

        :param volume: reference of volume to be unexported
        """
        LOG.debug("remove_export for volume: %s.", volume['id'])

        self._remove_target_volume(volume)

    def get_volume_stats(self, refresh=False):
        """Get volume stats.

        If 'refresh' is True, run update the stats first.
        """
        if refresh or self._stats is None:
            self._update_volume_stats()

        return self._stats

    def _update_volume_stats(self):
        """Retrieve stats info."""
        LOG.debug('Updating volume stats')

        pool_stats = self.ra.get_pool_stats()
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
            'host': self.ra.get_active_host(),
            'volume': self._pool
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

        LOG.debug('Total capacity: %d, '
                  'Free %d.',
                  self._stats['total_capacity_gb'],
                  self._stats['free_capacity_gb'])

    def _volume_exists(self, volume_id):
        """Return True if specified volume exists.

        :param volume_id:
        :return:
        """
        return self.ra.is_lun(volume_id)

    def _create_target(self, target_name, use_chap=True):
        """Creates target and handles exceptions

        Tryes to create target.
        :param target_name: name of target
        :param use_chap: flag for using chap
        """
        try:
            self.ra.create_target(target_name,
                                  use_chap=use_chap)

        except jexc.JDSSResourceExistsException:
            raise exception.VolumeBackendAPIException("target alrteady exists")
        except jexc.JDSSRESTException as ex:

            msg = (_('Unable to create target %(target)s '
                     'because of %(error)s.') % {'target': target_name,
                                                 'error': ex.message})
            raise exception.VolumeBackendAPIException(data=msg)

    def _attach_target_volume(self, target_name, vname, vid):
        """Attach target to volume and handles exceptions

        Tryes to set attach volume to specific target.
        In case of failure will remve target.
        :param target_name: name of target
        :param use_chap: flag for using chap
        """
        try:
            self.ra.attach_target_vol(target_name, vname)
        except jexc.JDSSRESTException as ex:
            err_msg = (_('Unable to attach target %(target)s to '
                         'volume %(volume)s because of %(error)s.') % {
                            'target': target_name,
                            'volume': vid,
                            'error': six.text_type(ex)})
            LOG.error(err_msg)
            try:
                self.ra.delete_target(target_name)
            except jexc.JDSSException as ex:
                raise exception.VolumeBackendAPIException(message=err_msg)
            raise exception.VolumeBackendAPIException(message=err_msg)

    def _set_target_credentials(self, target_name, cred):
        """Set CHAP configuration for target and handle exceptions

        Tryes to set CHAP credentials for specific target.
        In case of failure will remve target.
        :param target_name: name of target
        :param cred: CHAP user name and password
        """
        try:
            self.ra.create_target_user(target_name, cred)

        except jexc.JDSSRESTException as ex:
            try:
                self.ra.delete_target(target_name)
            except jexc.JDSSException as ex:
                pass

            err_msg = (_('Unable to create user %(user)s '
                         'for target %(target)s '
                         'because of %(error)s.') % {
                            'target': target_name,
                            'user': cred['name'],
                            'error': six.text_type(ex)})

            LOG.debug(err_msg)

            raise exception.VolumeBackendAPIException(data=err_msg)

    def _create_target_volume(self, volume, connector):
        """Creates target and attach volume to it

        :param volume: volume id
        :param connector: connector
        :return:
        """
        LOG.debug("create target and attach volume %s to it", volume['id'])

        target_name = self.jovian_target_prefix + volume["id"]
        vname = jcom.vname(volume['id'])

        auth = volume['provider_auth']

        if auth is None:
            msg = "Volume {} is missing provider_auth".format(volume['id'])
            raise exception.VolumeDriverException(msg)

        (_, auth_username, auth_secret) = auth.split()
        chap_cred = {"name": auth_username,
                     "password": auth_secret}

        # Create target
        self._create_target(target_name, True)

        # Attach volume
        self._attach_target_volume(target_name, vname, volume['id'])

        # Set credentials
        self._set_target_credentials(target_name, chap_cred)

    def _ensure_target_volume(self, volume):
        """Checks if target configured properly and volume is attached to it

        param: volume: volume structure
        """
        LOG.debug("ensure volume %s assigned to a proper target", volume['id'])

        target_name = self.jovian_target_prefix + volume["id"]

        auth = volume['provider_auth']

        if auth is None:
            msg = "Volume {} is missing provider_auth".format(volume['id'])
            raise exception.VolumeDriverException(msg)

        (_, auth_username, auth_secret) = auth.split()
        chap_cred = {"name": auth_username,
                     "password": auth_secret}

        if not self.ra.is_target(target_name):
            self._create_target(target_name, True)

        if not self.ra.is_target_lun(target_name, volume["id"]):
            self._attach_target_volume(target_name, vname, volume['id'])

        try:
            users = self.ra.get_target_user(target_name)
            if len(users) == 1:
                if users[0]['name'] == chap_cred['name']:
                    return
                else:
                    self.ra.delete_target_user(
                        target_name,
                        users[0]['name'])
            for user in users:
                self.ra.delete_target_user(
                    target_name,
                    user['name'])
            self._set_target_credentials(target_name, chap_cred)

        except jcom.JDSSException as err:
            self.ra.delete_target(target_name)
            raise exception.VolumeBackendAPIException(err.message)

    def _remove_target_volume(self, volume):
        """_remove_target_volume

        Ensure that volume is not attached to target and target do not exists.
        """
        target_name = self.jovian_target_prefix + volume['id']
        LOG.debug("Remove_export.")
        LOG.debug("detach volume:%(vol)s from target:%(targ)s.", {
            'vol': volume,
            'targ': target_name})

        try:
            self.ra.detach_target_vol(target_name, jcom.vname(volume['id']))
        except jexc.JDSSResourceNotFoundException as ex:
            LOG.debug('Failed to remove resource %(t)s because of %(err)s.', {
                't': target_name,
                'err': ex.args[0]})
        except jexc.JDSSRESTException as ex:
            LOG.debug('Failed to Terminate_connection for target %(targ)s'
                      'because of: %(err)s', {
                          'targ': target_name,
                          'err': ex.args[0]})

        LOG.debug("Delete target: %s.", target_name)

        try:
            self.ra.delete_target(target_name)
        except jexc.JDSSResourceNotFoundException as ex:
            LOG.debug('Failed to remove resource %(t)s because of %(err)s.', {
                't': target_name,
                'err': ex.args[0]})

        except jexc.JDSSException as ex:
            LOG.debug('Failed to Terminate_connection for target %(targ)s'
                      'because of: %(err)s', {
                          'targ': target_name,
                          'err': ex.args[0]})

    def _get_iscsi_properties(self, volume, connector):
        """Return dict according to cinder/driver.py implementation.

        :param volume:
        :return:
        """
        vname = jcom.vname(volume["id"])
        tname = self.jovian_target_prefix + volume['id']
        iface_info = []
        multipath = connector.get('multipath', False)
        if multipath:
            iface_info = self._get_active_ifaces()
            if not iface_info:
                raise exception.InvalidConfigurationValue(
                    'No available interfaces '
                    'or config excludes them')

        iscsi_properties = dict()

        if multipath:
            iscsi_properties['target_iqns'] = []
            iscsi_properties['target_portals'] = []
            iscsi_properties['target_luns'] = []
            LOG.debug('tpaths %s.', iface_info)
            for iface in iface_info:
                iscsi_properties['target_iqns'].append(
                    self.jovian_target_prefix +
                    vname)
                iscsi_properties['target_portals'].append(
                    iface +
                    ":" +
                    self.jovian_iscsi_target_portal_port)
                iscsi_properties['target_luns'].append(0)
        else:
            iscsi_properties['target_iqn'] = tname 
            iscsi_properties['target_portal'] = (
                self.ra.get_active_host()
                + ":"
                + self.jovian_iscsi_target_portal_port)

        iscsi_properties['target_discovered'] = False

        auth = volume['provider_auth']
        if auth:
            (auth_method, auth_username, auth_secret) = auth.split()

            iscsi_properties['auth_method'] = auth_method
            iscsi_properties['auth_username'] = auth_username
            iscsi_properties['auth_password'] = auth_secret

        iscsi_properties['target_lun'] = 0
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

        ip_settings = self.ra.get_target_ip_settings(target_name)

        LOG.debug("initialize_connection for %(volume)s %(ip)s."
                  "with ip list %(ip_list)s.",
                  {'volume': volume['id'],
                   'ip': connector['ip'],
                   'ip_list': str(ip_settings['allow_ip'])})

        try:
            self.ra.activate_target(target_name)
        except jexc.JDSSException:

            err_msg = (_('Unable to activate target %(target)s') % {
                'target': target_name})

            LOG.debug(err_msg)

            raise exception.VolumeBackendAPIException(message=err_msg)

        LOG.debug("providing connection info %s", iscsi_properties)
        return {
            'driver_volume_type': 'iscsi',
            'data': iscsi_properties,
        }

    def terminate_connection(self, volume, connector, force=False, **kwargs):
        """terminate_connection

        Disallow connection from connector by removing its ip
        from allowed ip list.
        """

        LOG.debug("terminate connection for %(volume)s ",
                  {'volume': volume['id']})

        target_name = self.jovian_target_prefix + volume["id"]

        try:
            self.ra.deactivate_target(target_name)
        except jexc.JDSSResourceNotFoundException:
            err_msg = (_('target %s do not exists') % target_name)
            LOG.debug(err_msg)

        except jexc.JDSSException as ex:
            err_msg = (_('Unable to deactivate target %(target)s') % {
                'target': target_name})
            LOG.debug(err_msg)
            raise exception.VolumeBackendAPIException(message=err_msg)

    def attach_volume(self,
                      context,
                      volume,
                      instance_uuid,
                      host_name,
                      mount_point):
        """Callback for volume attached to instance or host."""
        LOG.debug("Attach volume:"
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
        LOG.debug("Detach volume: %s.", volume['id'])

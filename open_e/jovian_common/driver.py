#    Copyright (c) 2023 Open-E, Inc.
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
from oslo_utils import units as o_units

from cinder import exception
from cinder.i18n import _
from cinder.volume.drivers.open_e.jovian_common import exception as jexc
from cinder.volume.drivers.open_e.jovian_common import jdss_common as jcom
from cinder.volume.drivers.open_e.jovian_common import rest

LOG = logging.getLogger(__name__)


class JovianDSSDriver(object):

    def __init__(self, config):

        self.configuration = config
        self._pool = self.configuration.get('jovian_pool', 'Pool-0')
        self.jovian_iscsi_target_portal_port = self.configuration.get(
            'target_port', 3260)

        self.jovian_target_prefix = self.configuration.get(
            'target_prefix',
            'iqn.2020-04.com.open-e.cinder:')
        self.jovian_chap_pass_len = self.configuration.get(
            'chap_password_len', 12)
        self.block_size = (
            self.configuration.get('jovian_block_size', '64K'))
        self.jovian_sparse = (
            self.configuration.get('san_thin_provision', True))
        self.jovian_ignore_tpath = self.configuration.get(
            'jovian_ignore_tpath', None)
        self.jovian_hosts = self.configuration.get(
            'san_hosts', [])

        self.ra = rest.JovianRESTAPI(config)

    def create_volume(self, volume_name, volume_size, sparse=False,
                      block_size=None):
        """Create a volume.

        :param str volume_name: volume id
        :param int volume_size: size in Gi
        :param bool sparse: thin or thick volume flag (default thin)
        :param int block_size: size of block (default None)

        :return: None
        """
        vname = jcom.vname(volume_name)
        LOG.debug("Create volume volume:%(name)s with size:%(size)s",
                  {'name': volume_name, 'size': volume_size})

        self.ra.create_lun(vname,
                           volume_size * o_units.Gi,
                           sparse=self.jovian_sparse,
                           block_size=self.block_size)
        return

    def _promote_newest_delete(self, vname, snapshots=None):
        '''Promotes and delete volume

        This function deletes volume.
        It will promote volume if needed before deletion.

        :param str vname: physical volume id
        :param list snapshots: snapshot data list (default None)

        :return: None
        '''

        if snapshots is None:
            try:
                snapshots = self.ra.get_snapshots(vname)
            except jexc.JDSSResourceNotFoundException:
                LOG.debug('volume %s dne, it was already '
                          'deleted', vname)
                return

        bsnaps = self._list_busy_snapshots(vname, snapshots)

        if len(bsnaps) != 0:

            promote_target = None

            sname = jcom.get_newest_snapshot_name(bsnaps)

            for snap in bsnaps:
                if snap['name'] == sname:
                    cvnames = jcom.snapshot_clones(snap)
                    for cvname in cvnames:
                        if jcom.is_volume(cvname):
                            promote_target = cvname
                        if jcom.is_snapshot(cvname):
                            self._promote_newest_delete(cvname)
                        if jcom.is_hidden(cvname):
                            self._promote_newest_delete(cvname)
                    break

            if promote_target is None:
                self._promote_newest_delete(vname)
                return

            self.ra.promote(vname, sname, promote_target)

        self._delete_vol_with_source_snap(vname, recursive=True)

    def _delete_vol_with_source_snap(self, vname, recursive=False):
        '''Delete volume and its source snapshot if required

        This function deletes volume.
        If volume is a clone it will check its source snapshot and
        deletes if it is not a dedicated snapshot, but an intermediate one.

        :param str vname: physical volume id
        :param bool recursive: recursive flag (default False)

        :return: None
        '''
        vol = None

        try:
            vol = self.ra.get_lun(vname)
        except jexc.JDSSResourceNotFoundException:
            LOG.debug('unable to get volume %s info, '
                      'assume it was already delleted', vname)
            return
        try:
            self.ra.delete_lun(vname,
                               force_umount=True,
                               recursively_children=recursive)
        except jexc.JDSSResourceNotFoundException:
            LOG.debug('volume %s dne, it was already '
                      'deleted', vname)
            return

        if vol is not None and \
                'origin' in vol and \
                vol['origin'] is not None:
            if jcom.is_volume(jcom.origin_snapshot(vol)) or \
                    jcom.is_hidden(jcom.origin_snapshot(vol)):
                self.ra.delete_snapshot(jcom.origin_volume(vol),
                                        jcom.origin_snapshot(vol),
                                        recursively_children=True,
                                        force_umount=True)

    def _clean_garbage_resources(self, vname, snapshots=None):
        '''Removes resources that is not related to volume

        Goes through volume snapshots and it clones to identify one
        that is clearly not related to vname volume and therefore
        have to be deleted.

        :param str vname: physical volume id
        :param list snapshots: list of snapshot info dictionaries

        :return: updated list of snapshots
        '''

        if snapshots is None:
            try:
                snapshots = self.ra.get_snapshots(vname)
            except jexc.JDSSResourceNotFoundException:
                LOG.debug('volume %s dne, it was already '
                          'deleted', vname)
                return
        update = False
        for snap in snapshots:
            if jcom.is_volume(jcom.sname_from_snap(snap)):
                cvnames = jcom.snapshot_clones(snap)
                if len(cvnames) == 0:
                    self._delete_snapshot(vname, jcom.sname_from_snap(snap))
                    update = True
            if jcom.is_snapshot(jcom.sname_from_snap(snap)):
                cvnames = jcom.snapshot_clones(snap)
                for cvname in cvnames:
                    if jcom.is_hidden(cvname):
                        self._promote_newest_delete(cvname)
                        update = True
                    if jcom.is_snapshot(cvname):
                        if jcom.idname(vname) != jcom.vid_from_sname(cvname):
                            self._promote_newest_delete(cvname)
                            update = True
            if update:
                snapshots = self.ra.get_snapshots(vname)
            return snapshots

    def _list_busy_snapshots(self, vname, snapshots,
                             exclude_mountpoints=False,
                             exclude_dedicated_volumes=False) -> list:
        """List all volume snapshots with clones

        Goes through provided list of snapshots.
        If additional parameters are given, will filter list of snapshots
        accordingly.

        Keyword arguments:
        :param str vname: zvol id
        :param list snapshots: list of snapshots data dicts
        :param bool exclude_mountpoints -- list snapshot that is mountable,
                                   has snapshot like clone (default False)
        :param bool exclude_dedicated_volumes: list snapshots that has clones
                                        (default False)

        :return: filtered list of snapshot data dicts
        :rtype: list
        """

        out = []
        for snap in snapshots:
            clones = jcom.snapshot_clones(snap)
            add = False
            for cvname in clones:
                if exclude_mountpoints and jcom.is_snapshot(cvname):
                    continue
                if exclude_dedicated_volumes and jcom.is_volume(cvname):
                    continue
                add = True
            if add:
                out.append(snap)

        return out

    def _list_iddle_snapshots(self, snapshots):
        """List iddle snapshots

        Go through list of snapshots and return
        thouse who have no clones
        """

        out = []
        for snap in snapshots:
            if len(jcom.snapshot_clones(snap)) == 0:
                out.append(snap)

        return out

    def _list_volume_snapshots_mount_points(self, vname, snapshots):

        out = []
        for snap in snapshots:
            if jcom.is_snapshot(snap['name']):
                clones = jcom.snapshot_clones(snap)
                for clone in [c for c in clones if jcom.is_snapshot(c)]:
                    out.append(clone)
        return out

    def _list_volume_snapshot_volumes(self, vname, snap,
                                      clone_from_volume=False):

        clones = jcom.snapshot_clones(snap)
        out = []
        for clone in [c for c in clones if jcom.is_volume(c)]:
            if clone_from_volume:
                if jcom.is_volume(snap['name']):
                    out.append(clone)
            else:
                out.append(clone)
        return out

    def _delete_volume_snapshot_mount_point(self, mpname):
        try:
            self.ra.delete_lun(mpname,
                               force_umount=True,
                               recursively_children=True)
        except jexc.JDSSResourceNotFoundException:
            LOG.debug('unable to delete mount for snapshot %s',
                      mpname)
            return None

        return

    def _delete_volume(self, vname, cascade=False):

        try:
            self.ra.delete_lun(vname,
                               force_umount=True,
                               recursively_children=cascade)
        except jexc.JDSSResourceIsBusyException:
            LOG.debug('unable to conduct direct volume %s deletion', vname)
        except jexc.JDSSResourceNotFoundException:
            LOG.debug('volume %s dne, it was already '
                      'deleted', vname)
            return
        except jexc.JDSSRESTException as jerr:
            LOG.debug(
                "Unable to delete physical volume %(volume)s "
                "with error %(err)s.", {
                    "volume": vname,
                    "err": jerr})
        else:
            LOG.debug('in place deletion suceeded')
            return

        snapshots = None
        try:
            snapshots = self.ra.get_snapshots(vname)
        except jexc.JDSSResourceNotFoundException:
            LOG.debug('volume %s dne, it was already '
                      'deleted', vname)
            return

        if cascade is False:
            bsnaps = self._list_busy_snapshots(vname,
                                               snapshots,
                                               exclude_dedicated_volumes=True)
            if len(bsnaps) > 0:
                raise exception.VolumeIsBusy('Volume has snapshots')

        snaps = self._clean_garbage_resources(vname, snapshots)

        self._promote_newest_delete(vname, snapshots=snaps)

    def delete_volume(self, volume_name, cascade=False):
        """Delete volume

        :param volume: volume reference
        :param cascade: remove snapshots of a volume as well
        """
        vname = jcom.vname(volume_name)

        LOG.debug('deleating volume %s', vname)

        self._delete_volume(vname, cascade=cascade)

    def _hide_object(self, vname):
        """Mark volume/snapshot as hidden

        :param vname: physical volume name
        """
        rename = {'name': jcom.hidden(vname)}
        try:
            self.ra.modify_lun(vname, rename)
        except jexc.JDSSException as jerr:
            emsg = _('Failure in hiding %(object)s, err: %(error)s,'
                     ' object has to be removed manually') % {'object': vname,
                                                              'error': jerr}
            LOG.warning(emsg)
            raise exception.VolumeBackendAPIException(emsg)

    def _unhide_object(self, hvname, is_snapshot=False):
        """Un mark volume/snapshot as hidden

        :param vname: physical volume name
        """
        vname = jcom.vname(jcom.idname(hvname))
        rename = {'name': jcom.hidden(vname)}
        try:
            self.ra.modify_lun(hvname, rename)
        except jexc.JDSSException as jerr:
            emsg = _('Failure in un hiding %(object)s, err: %(error)s,'
                     ' object has to be removed manually') % {'object': vname,
                                                              'error': jerr}
            LOG.warning(emsg)
            raise exception.VolumeBackendAPIException(emsg)

    def _clone_object(self, cvname, sname, ovname,
                      sparse=None, create_snapshot=False):
        """Creates a clone of specified object

        Will create snapshot if it is not provided

        :param: cvname: clone volume name
        :param: sname: snapshot name
        :param: ovname: original volume name
        :param: sparse: sparsines property of new volume, can take values of:
                        True
        """
        LOG.debug('cloning %(ovname)s to %(coname)s', {
            "ovname": ovname,
            "coname": cvname})

        if create_snapshot:
            self.ra.create_snapshot(ovname, sname)
        try:
            self.ra.create_volume_from_snapshot(
                cvname,
                sname,
                ovname,
                sparse=sparse)
        except jexc.JDSSResourceExistsException as jerr:
            raise exception.Duplicate() from jerr
        except jexc.JDSSException as jerr:
            # This is a garbege collecting section responsible for cleaning
            # all the mess of request failed
            if create_snapshot:
                try:
                    self.ra.delete_snapshot(ovname,
                                            cvname,
                                            recursively_children=True,
                                            force_umount=True)
                except jexc.JDSSException as jerrd:
                    LOG.warning("Because of %s physical snapshot %s of volume"
                                " %s have to be removed manually",
                                jerrd,
                                sname,
                                ovname)

            raise jerr

    def resize_volume(self, volume_name, new_size):
        """Extend an existing volume.

        :param str volume_name: volume id
        :param int new_size: volume new size in Gi
        """
        LOG.debug("Extend volume:%(name)s to size:%(size)s",
                  {'name': volume_name, 'size': new_size})

        self.ra.extend_lun(jcom.vname(volume_name),
                           int(new_size) * o_units.Gi)

    def _resize_if_neccessary(self, vname, size, vol=None):
        """Resizes volume to size

        Method will resize zvol with vname to size specified with size
        or do nothing if zvol already have required size.
        Method will use vol struct(in case one is provided) to make decision
        if extension is needed or will requst vol data itself

        :param str vname: zvol name
        :param int size: target size in Gi
        :param dict vol: volume reference
        :raises JDSSException: if request fils

        :return: None
        """
        vsize = None
        if vol:
            vsize = vol['volsize']
        else:
            vsize = int(self.ra.get_lun(vname)['volsize'])

        if int(vsize) != o_units.Gi * int(size):
            self.resize_volume(vname, int(size))

        return

    def create_cloned_volume(self,
                             clone_name,
                             volume_name,
                             size,
                             snapshot_name=None):
        """Create a clone of the specified volume.

        :param str clone_name: new volume id
        :param volume_name: original volume id
        :param int size: size in Gi
        """
        cvname = jcom.vname(clone_name)

        ovname = jcom.vname(volume_name)

        LOG.debug('clone volume %(id)s to %(id_clone)s', {
            "id": volume_name,
            "id_clone": clone_name})

        if snapshot_name:
            sname = jcom.sname(snapshot_name, volume_name)
            self._clone_object(cvname, sname, ovname, create_snapshot=False)
        else:
            sname = jcom.vname(clone_name)
            self._clone_object(cvname, sname, ovname, create_snapshot=True)

        clone_size = 0

        try:
            clone_size = int(self.ra.get_lun(cvname)['volsize'])
        except jexc.JDSSException as jerr:

            self.delete_volume(clone_name, cascade=False)
            raise exception.VolumeBackendAPIException(
                _("Fail in cloning volume %(vol)s to %(clone)s.") % {
                    'vol': volume_name, 'clone': clone_name}) from jerr

        try:
            if int(clone_size) < o_units.Gi * int(size):
                self.resize_volume(volume_name, int(size))

        except jexc.JDSSException as jerr:
            # If volume can't be set to a proper size make sure to clean it
            # before failing
            try:
                self.delete_volume(clone_name, cascade=False)
            except jexc.JDSSException as jerrex:
                LOG.warning("Error %s during cleaning failed volume %s",
                            jerrex, volume_name)
                raise jerr from jerrex

    def create_snapshot(self, snapshot_name, volume_name):
        """Create snapshot of existing volume.

        :param str snapshot_name: new snapshot id
        :param str volume_name: original volume id
        """
        LOG.debug('create snapshot %(snap)s for volume %(vol)s', {
            'snap': snapshot_name,
            'vol': volume_name})

        vname = jcom.vname(volume_name)
        sname = jcom.sname(snapshot_name, volume_name)

        self.ra.create_snapshot(vname, sname)
        # TODO: remove this
        self.ra.get_snapshots(vname)

    def _delete_snapshot(self, vname, sname):
        """Delete snapshot

        This method will delete snapshot mount point and snapshot if possible

        :param str vname: zvol name
        :param dict snap: snapshot info dictionary

        :return: None
        """

        try:
            self.ra.delete_snapshot(vname, sname, force_umount=True)
        except jexc.JDSSResourceIsBusyException:
            LOG.debug('Direct deletion of snapshot %s failed', vname)
        else:
            return

        snap = self.ra.get_snapshot(vname, sname)

        clones = jcom.snapshot_clones(snap)
        busy = False
        for cvname in clones:
            if jcom.is_snapshot(cvname):
                self._promote_newest_delete(cvname)
            if jcom.is_volume(cvname):
                LOG.debug('Will not delete snap %(snap)s,'
                          'becasue it is used by %(vol)',
                          {'snap': sname,
                           'vol': cvname})
                busy = True
        if busy:
            return
        try:
            self.ra.delete_snapshot(vname, sname, force_umount=True)
        except jexc.JDSSResourceIsBusyException:
            LOG.debug('Unable to delete snap %(snap)s because it is busy',
                      {'snap': jcom.sname_from_snap(snap)})

    def delete_snapshot(self, volume_name, snapshot_name):
        """Delete snapshot of existing volume.

        :param str volume_name: volume id
        :param str snapshot_name: snapshot id
        """
        vname = jcom.vname(volume_name)
        sname = jcom.sname(snapshot_name, volume_name)

        self._delete_snapshot(vname, sname)

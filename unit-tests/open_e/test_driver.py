#import re
#from unittest import mock
#
#from oslo_utils import units as o_units
#
#from cinder import context
#from cinder import exception
#from cinder.tests.unit import fake_snapshot
#from cinder.tests.unit import fake_volume
#from cinder.tests.unit import test
#from cinder.volume.drivers.open_e import iscsi
#from cinder.volume.drivers.open_e.jovian_common import driver
#from cinder.volume.drivers.open_e.jovian_common import exception as jexc
#from cinder.volume.drivers.open_e.jovian_common import jdss_common as jcom
#
#UUID_1 = '12345678-1234-1234-1234-000000000001'
#UUID_2 = '12345678-1234-1234-1234-000000000002'
#UUID_3 = '12345678-1234-1234-1234-000000000003'
#UUID_4 = '12345678-1234-1234-1234-000000000004'
#
#UUID_S1 = '12345678-1234-1234-1234-100000000001'
#UUID_S2 = '12345678-1234-1234-1234-100000000002'
#UUID_S3 = '12345678-1234-1234-1234-100000000003'
#UUID_S4 = '12345678-1234-1234-1234-100000000004'
#
#CONFIG_OK = {
#    'san_hosts': ['192.168.0.2'],
#    'san_api_port': 82,
#    'driver_use_ssl': 'true',
#    'jovian_rest_send_repeats': 3,
#    'jovian_recovery_delay': 60,
#    'jovian_user': 'admin',
#    'jovian_password': 'password',
#    'jovian_ignore_tpath': [],
#    'target_port': 3260,
#    'jovian_pool': 'Pool-0',
#    'target_prefix': 'iqn.2020-04.com.open-e.cinder:',
#    'chap_password_len': 12,
#    'san_thin_provision': False,
#    'jovian_block_size': '128K'
#}
#
#CONFIG_BLOCK_SIZE = {
#    'san_hosts': ['192.168.0.2'],
#    'san_api_port': 82,
#    'driver_use_ssl': 'true',
#    'jovian_rest_send_repeats': 3,
#    'jovian_recovery_delay': 60,
#    'jovian_user': 'admin',
#    'jovian_password': 'password',
#    'jovian_ignore_tpath': [],
#    'target_port': 3260,
#    'jovian_pool': 'Pool-0',
#    'target_prefix': 'iqn.2020-04.com.open-e.cinder:',
#    'chap_password_len': 12,
#    'san_thin_provision': False,
#    'jovian_block_size': '64K'
#}
#
#CONFIG_BAD_BLOCK_SIZE = {
#    'san_hosts': ['192.168.0.2'],
#    'san_api_port': 82,
#    'driver_use_ssl': 'true',
#    'jovian_rest_send_repeats': 3,
#    'jovian_recovery_delay': 60,
#    'jovian_user': 'admin',
#    'jovian_password': 'password',
#    'jovian_ignore_tpath': [],
#    'target_port': 3260,
#    'jovian_pool': 'Pool-0',
#    'target_prefix': 'iqn.2020-04.com.open-e.cinder:',
#    'chap_password_len': 12,
#    'san_thin_provision': False,
#    'jovian_block_size': '61K'
#}
#
#CONFIG_BACKEND_NAME = {
#    'san_hosts': ['192.168.0.2'],
#    'san_api_port': 82,
#    'driver_use_ssl': 'true',
#    'jovian_rest_send_repeats': 3,
#    'jovian_recovery_delay': 60,
#    'jovian_user': 'admin',
#    'jovian_password': 'password',
#    'jovian_ignore_tpath': [],
#    'target_port': 3260,
#    'jovian_pool': 'Pool-0',
#    'target_prefix': 'iqn.2020-04.com.open-e.cinder:',
#    'chap_password_len': 12,
#    'san_thin_provision': False,
#    'volume_backend_name': 'JovianDSS',
#    'reserved_percentage': 10,
#    'jovian_block_size': '128K'
#}
#
#CONFIG_MULTI_HOST = {
#    'san_hosts': ['192.168.0.2', '192.168.0.3'],
#    'san_api_port': 82,
#    'driver_use_ssl': 'true',
#    'jovian_rest_send_repeats': 3,
#    'jovian_recovery_delay': 60,
#    'jovian_user': 'admin',
#    'jovian_password': 'password',
#    'jovian_ignore_tpath': [],
#    'target_port': 3260,
#    'jovian_pool': 'Pool-0',
#    'target_prefix': 'iqn.2020-04.com.open-e.cinder:',
#    'chap_password_len': 12,
#    'san_thin_provision': False,
#    'volume_backend_name': 'JovianDSS',
#    'reserved_percentage': 10,
#    'jovian_block_size': '128K'
#}
#
#SNAPSHOTS_CASCADE_1 = [
#    {"name": jcom.sname(UUID_S1, UUID_1),
#     "clones": "Pool-0/" + jcom.sname(UUID_S1, UUID_1)},
#    {"name": jcom.sname(UUID_S1, UUID_2),
#     "clones": "Pool-0/" + jcom.sname(UUID_S1, UUID_2)},
#    {"name": jcom.sname(UUID_S1, UUID_3),
#     "clones": "Pool-0/" + jcom.sname(UUID_S1, UUID_3)}]
#
#SNAPSHOTS_CASCADE_2 = [
#    {"name": jcom.sname(UUID_S1, UUID_1),
#     "clones": "Pool-0/" + jcom.sname(UUID_S1, UUID_1)},
#    {"name": jcom.vname(UUID_2),
#     "clones": "Pool-0/" + jcom.vname(UUID_2)},
#    {"name": jcom.sname(UUID_S1, UUID_3),
#     "clones": "Pool-0/" + jcom.sname(UUID_S1, UUID_3)}]
#
#SNAPSHOTS_CASCADE_3 = [
#    {"name": jcom.vname(UUID_4),
#     "clones": "Pool-0/" + jcom.vname(UUID_4)}]
#
#SNAPSHOTS_EMPTY = []
#
#SNAPSHOTS_CLONE = [
#    {"name": jcom.vname(UUID_1),
#     "clones": "Pool-0/" + jcom.vname(UUID_1)}]
#
#SNAPSHOTS_GARBAGE = [
#    {"name": jcom.sname(UUID_S1, UUID_1),
#     "clones": "Pool-0/" + jcom.vname(UUID_2)},
#    {"name": jcom.sname(UUID_S1, UUID_2),
#     "clones": ""}]
#
#SNAPSHOTS_RECURSIVE_1 = [
#    {"name": jcom.sname(UUID_S1, UUID_1),
#     "clones": "Pool-0/" + jcom.sname(UUID_S1, UUID_1)},
#    {"name": jcom.sname(UUID_S1, UUID_2),
#     "clones": "Pool-0/" + jcom.hidden(UUID_2)}]
#
#SNAPSHOTS_RECURSIVE_CHAIN_1 = [
#    {"name": jcom.sname(UUID_S1, UUID_3),
#     "clones": "Pool-0/" + jcom.hidden(UUID_3)}]
#
#SNAPSHOTS_RECURSIVE_CHAIN_2 = [
#    {"name": jcom.vname(UUID_2),
#     "clones": "Pool-0/" + jcom.hidden(UUID_2)}]
#
#
#def get_jdss_exceptions():
#
#    out = [jexc.JDSSException(reason="Testing"),
#           jexc.JDSSRESTException(request="ra request", reason="Testing"),
#           jexc.JDSSRESTProxyException(host="test_host", reason="Testing"),
#           jexc.JDSSResourceNotFoundException(res="test_resource"),
#           jexc.JDSSVolumeNotFoundException(volume="test_volume"),
#           jexc.JDSSSnapshotNotFoundException(snapshot="test_snapshot"),
#           jexc.JDSSResourceExistsException(res="test_resource"),
#           jexc.JDSSSnapshotExistsException(snapshot="test_snapshot"),
#           jexc.JDSSVolumeExistsException(volume="test_volume"),
#           jexc.JDSSSnapshotIsBusyException(snapshot="test_snapshot")]
#
#    return out
#    
#
#class TestOpenEJovianDSSDriver(test.TestCase):
#
#    def get_driver(self, config):
#        ctx = context.get_admin_context()
#
#        cfg = mock.Mock()
#        cfg.append_config_values.return_value = None
#        cfg.get = lambda val, default: config.get(val, default)
#
#        jdssd = iscsi.JovianISCSIDriver()
#
#        jdssd.configuration = cfg
#        lib_to_patch = ('cinder.volume.drivers.open_e.jovian_common.rest.'
#                        'JovianRESTAPI')
#        with mock.patch(lib_to_patch) as ra:
#            ra.is_pool_exists.return_value = True
#            jdssd.do_setup(ctx)
#        jdssd.ra = mock.Mock()
#        return jdssd, ctx
#
#    def get_iscsi_driver(self, config):
#        ctx = context.get_admin_context()
#
#        cfg = mock.Mock()
#        cfg.append_config_values.return_value = None
#        cfg.get = lambda val, default: config.get(val, default)
#
#        jdssd = iscsi.JovianISCSIDriver()
#
#        jdssd.configuration = cfg
#        lib_to_patch = ('cinder.volume.drivers.open_e.jovian_common.rest.'
#                        'JovianRESTAPI')
#        with mock.patch(lib_to_patch) as ra:
#            ra.is_pool_exists.return_value = True
#            jdssd.do_setup(ctx)
#        jdssd.ra = mock.Mock()
#        jdssd.driver = mock.Mock()
#        return jdssd, ctx
#
#    def get_jdss_driver(self, config):
#        ctx = context.get_admin_context()
#
#        cfg = mock.Mock()
#        cfg.append_config_values.return_value = None
#        cfg.get = lambda val, default: config.get(val, default)
#
#        jdssd = iscsi.JovianISCSIDriver()
#
#        jdssd.configuration = cfg
#        lib_to_patch = ('cinder.volume.drivers.open_e.jovian_common.driver.'
#                        'JovianRESTAPI')
#        with mock.patch(lib_to_patch) as ra:
#            ra.is_pool_exists.return_value = True
#            jdssd.do_setup(ctx)
#        jdssd.ra = mock.Mock()
#        return jdssd, ctx
#
#    def start_patches(self, patches):
#        for p in patches:
#            p.start()
#
#    def stop_patches(self, patches):
#        for p in patches:
#            p.stop()
#    def test_clean_garbage_snapshots(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#        o_vname = jcom.vname(UUID_1)
#        o_snaps = SNAPSHOTS_GARBAGE.copy()
#
#        jdssd.ra.delete_snapshot.return_value = None
#        jdssd._clean_garbage_snapshots(o_vname, o_snaps)
#        jdssd.ra.delete_snapshot.assert_called_once_with(
#            o_vname,
#            SNAPSHOTS_GARBAGE[1]["name"])
#        # Test exception handling
#        for exc in get_jdss_exceptions():
#            o_snaps = SNAPSHOTS_GARBAGE.copy()
#            jdssd.ra.delete_snapshot.side_effect = exc
#            try:
#                jdssd._clean_garbage_snapshots(o_vname, o_snaps)
#            except Exception as err:
#                self.assertIsInstance(err, exception.VolumeBackendAPIException)
#
#    def test_cascade_volume_delete_snapshots(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#        o_vname = jcom.vname(UUID_1)
#
#        # Volume with 3 snapshots and no descendants
#        # We should delete snapshots and then cal for volume deletion
#        o_snaps = SNAPSHOTS_CASCADE_1.copy()
#
#        jdssd.ra.modify_lun.return_value = None
#        jdssd.ra.delete_snapshot.return_value = None
#        jdssd.ra.get_snapshots.side_effect = [
#            SNAPSHOTS_EMPTY,
#            SNAPSHOTS_EMPTY,
#            SNAPSHOTS_EMPTY]
#
#        #with mock.patch.object(jdssd, "_gc_delete", return_value=None) as gc:
#        #    jdssd._cascade_volume_delete(o_vname, o_snaps)
#        #    gc.assert_called_once_with(o_vname)
#        delete_snapshot_expected = [
#            mock.call(o_vname,
#                      SNAPSHOTS_CASCADE_1[0]["name"],
#                      recursively_children=True,
#                      recursively_dependents=True,
#                      force_umount=True),
#            mock.call(o_vname,
#                      SNAPSHOTS_CASCADE_1[1]["name"],
#                      recursively_children=True,
#                      recursively_dependents=True,
#                      force_umount=True),
#            mock.call(o_vname,
#                      SNAPSHOTS_CASCADE_1[2]["name"],
#                      recursively_children=True,
#                      recursively_dependents=True,
#                      force_umount=True)]
#        jdssd.ra.delete_snapshot.assert_has_calls(delete_snapshot_expected)
#
#    def test_cascade_volume_delete_with_clone(self):
#        # Volume with 2 snapshots and 1 clone
#        # We should delete snapshots and then cal for volume hiding
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#        o_vname = jcom.vname(UUID_1)
#        o_snaps = SNAPSHOTS_CASCADE_2.copy()
#
#        jdssd.ra.modify_lun.return_value = None
#        jdssd.ra.delete_snapshot.return_value = None
#        jdssd.ra.get_snapshots.side_effect = [
#            SNAPSHOTS_EMPTY,
#            SNAPSHOTS_EMPTY]
#
#        patches = [mock.patch.object(jdssd, "_gc_delete"),
#                   mock.patch.object(jdssd, "_hide_object")]
#
#        self.start_patches(patches)
#
#        jdssd._cascade_volume_delete(o_vname, o_snaps)
#
#        jdssd._hide_object.assert_called_once_with(o_vname)
#        jdssd._gc_delete.assert_not_called()
#
#        self.stop_patches(patches)
#
#        delete_snapshot_expected = [
#            mock.call(o_vname,
#                      SNAPSHOTS_CASCADE_2[0]["name"],
#                      recursively_children=True,
#                      recursively_dependents=True,
#                      force_umount=True),
#            mock.call(o_vname,
#                      SNAPSHOTS_CASCADE_2[2]["name"],
#                      recursively_children=True,
#                      recursively_dependents=True,
#                      force_umount=True)]
#        jdssd.ra.delete_snapshot.assert_has_calls(delete_snapshot_expected)
#
#    def test_cascade_volume_delete_snapshot_clone(self):
#        # Volume with 3 snapshots and 1 clone of a snapshots
#        # We should delete childless snapshots
#        #           and then cal for volume deletion
#
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#        o_vname = jcom.vname(UUID_1)
#        o_snaps = SNAPSHOTS_CASCADE_1.copy()
#
#        jdssd.ra.modify_lun.return_value = None
#        jdssd.ra.delete_snapshot.return_value = None
#        jdssd.ra.get_snapshots.side_effect = [
#            SNAPSHOTS_EMPTY,
#            SNAPSHOTS_CASCADE_3.copy(),
#            SNAPSHOTS_EMPTY]
#        get_snapshots = [
#            mock.call(SNAPSHOTS_CASCADE_1[0]['name']),
#            mock.call(SNAPSHOTS_CASCADE_1[1]['name']),
#            mock.call(SNAPSHOTS_CASCADE_1[2]['name'])
#        ]
#        hide_object_expected = [
#            mock.call(SNAPSHOTS_CASCADE_1[1]["name"]),
#            mock.call(o_vname)]
#
#        #patches = [mock.patch.object(jdssd, "_gc_delete"),
#        #           mock.patch.object(jdssd, "_hide_object")]
#
#        #self.start_patches(patches)
#
#        #jdssd._cascade_volume_delete(o_vname, o_snaps)
#        #jdssd._hide_object.assert_has_calls(hide_object_expected)
#        #jdssd._gc_delete.assert_not_called()
#
#        #self.stop_patches(patches)
#
#        jdssd.ra.get_snapshots.assert_has_calls(get_snapshots)
#
#        delete_snapshot_expected = [
#            mock.call(o_vname,
#                      SNAPSHOTS_CASCADE_2[0]["name"],
#                      recursively_children=True,
#                      recursively_dependents=True,
#                      force_umount=True),
#            mock.call(o_vname,
#                      SNAPSHOTS_CASCADE_2[2]["name"],
#                      recursively_children=True,
#                      recursively_dependents=True,
#                      force_umount=True)]
#        jdssd.ra.delete_snapshot.assert_has_calls(delete_snapshot_expected)
#
#    def test_delete_volume_with_snapshots(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#        vol = fake_volume.fake_volume_obj(ctx)
#        vol.id = UUID_1
#        vname = jcom.vname(UUID_1)
#        jdssd.ra.get_snapshots.side_effect = [SNAPSHOTS_CASCADE_1.copy()]
#
#        patches = [mock.patch.object(jdssd, "_cascade_volume_delete"),
#                   mock.patch.object(jdssd, "_gc_delete"),
#                   mock.patch.object(jdssd, "_hide_object")]
#
#        self.start_patches(patches)
#
#        jdssd.delete_volume(vol, cascade=False)
#        jdssd._gc_delete.assert_not_called()
#        jdssd._cascade_volume_delete.assert_not_called()
#        jdssd._hide_object.assert_called_once_with(vname)
#
#        self.stop_patches(patches)
#
#        jdssd.ra.get_snapshots.assert_called_once_with(vname)
#
#    def test_delete_volume_without_snapshots(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#        vol = fake_volume.fake_volume_obj(ctx)
#        vol.id = UUID_1
#        vname = jcom.vname(UUID_1)
#        jdssd.ra.get_snapshots.side_effect = [SNAPSHOTS_EMPTY.copy()]
#
#        patches = [mock.patch.object(jdssd, "_cascade_volume_delete"),
#                   mock.patch.object(jdssd, "_gc_delete"),
#                   mock.patch.object(jdssd, "_hide_object")]
#
#        self.start_patches(patches)
#
#        jdssd.delete_volume(vol, cascade=False)
#        jdssd._gc_delete.assert_called_once_with(vname)
#        jdssd._cascade_volume_delete.assert_not_called()
#        jdssd._hide_object.assert_not_called()
#
#        self.stop_patches(patches)
#
#        jdssd.ra.get_snapshots.assert_called_once_with(vname)
#
#    def test_delete_snapshot_no_child(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#
#        sname = jcom.sname(UUID_2)
#
#        snap = fake_snapshot.fake_snapshot_obj(ctx, id=UUID_2)
#
#        jdssd.ra.get_snapshots.return_value = SNAPSHOTS_EMPTY
#        patches = [
#            mock.patch.object(
#                jdssd,
#                "_clean_garbage_snapshots",
#                return_value=SNAPSHOTS_EMPTY),
#            mock.patch.object(jdssd, "_clone_object", return_value=None),
#            mock.patch.object(jdssd, "_hide_object", return_value=None),
#            mock.patch.object(jdssd, "_gc_delete", return_value=None)]
#
#        self.start_patches(patches)
#
#        jdssd.create_snapshot(snap)
#
#        jdssd.delete_snapshot(snap)
#        jdssd._gc_delete.assert_called_once_with(sname)
#        jdssd._hide_object.assert_not_called()
#        jdssd._clean_garbage_snapshots.assert_called_once_with(
#            sname,
#            SNAPSHOTS_EMPTY)
#        self.stop_patches(patches)
#
#    def test_delete_snapshot_has_clone(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#
#        sname = jcom.sname(UUID_2)
#
#        snap = fake_snapshot.fake_snapshot_obj(ctx, id=UUID_2)
#
#        jdssd.ra.get_snapshots.return_value = SNAPSHOTS_EMPTY
#        patches = [
#            mock.patch.object(
#                jdssd,
#                "_clean_garbage_snapshots",
#                return_value=SNAPSHOTS_CLONE),
#            mock.patch.object(jdssd, "_clone_object", return_value=None),
#            mock.patch.object(jdssd, "_hide_object", return_value=None),
#            mock.patch.object(jdssd, "_gc_delete", return_value=None)]
#
#        self.start_patches(patches)
#
#        jdssd.create_snapshot(snap)
#
#        jdssd.delete_snapshot(snap)
#        jdssd._gc_delete.assert_not_called()
#        jdssd._hide_object.assert_called_once_with(sname)
#        jdssd._clean_garbage_snapshots.assert_called_once_with(
#            sname,
#            SNAPSHOTS_EMPTY)
#        self.stop_patches(patches)
#
#    def test_delete_snapshot(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#
#        sname = jcom.sname(UUID_S1, UUID_1)
#
#        snap = fake_snapshot.fake_snapshot_obj(ctx, id=UUID_S11)
#
#        jdssd.ra.get_snapshots.return_value = SNAPSHOTS_EMPTY
#        patches = [
#            mock.patch.object(
#                jdssd,
#                "_clean_garbage_snapshots",
#                return_value=SNAPSHOTS_EMPTY),
#            mock.patch.object(jdssd, "_clone_object", return_value=None),
#            mock.patch.object(jdssd, "_hide_object", return_value=None),
#            mock.patch.object(jdssd, "_gc_delete", return_value=None)]
#
#        self.start_patches(patches)
#
#        jdssd.create_snapshot(snap)
#
#        jdssd.delete_snapshot(snap)
#        jdssd._gc_delete.assert_called_once_with(sname)
#        jdssd._hide_object.assert_not_called()
#        jdssd._clean_garbage_snapshots.assert_called_once_with(
#            sname,
#            SNAPSHOTS_EMPTY)
#        self.stop_patches(patches)
#
#    def test_create_volume_from_snapshot(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#
#        origin_sname = jcom.sname(UUID_1)
#
#        clone_vname = jcom.vname(UUID_2)
#
#        orig_snap = fake_snapshot.fake_snapshot_obj(ctx)
#        orig_snap.id = UUID_1
#
#        clone_vol = fake_volume.fake_volume_obj(ctx)
#        clone_vol.id = UUID_2
#        clone_vol.size = 1
#
#        host = CONFIG_OK["san_hosts"][0]
#        port = CONFIG_OK["target_port"]
#        target_name = CONFIG_OK["target_prefix"] + UUID_2
#
#        location = '{host}:{port},1 {name} 0'.format(
#            host=host,
#            port=port,
#            name=target_name
#        )
#
#        cred_format = (r"CHAP [0-9,a-z,A-Z]{{{name_len}}} "
#                       "[0-9,a-z,A-Z]{{{pass_len}}}").format(
#            name_len=8,
#            pass_len=CONFIG_OK['chap_password_len'])
#
#        patches = [
#            mock.patch.object(jdssd, "_clone_object", return_value=None),
#            mock.patch.object(jdssd, "extend_volume", return_value=None),
#            mock.patch.object(
#                jdssd,
#                "_get_provider_location",
#                return_value=location),
#            mock.patch.object(
#                jdssd,
#                "_get_provider_auth",
#                return_value=cred_format)]
#
#        jdssd.ra.get_lun.return_value = {
#            'vscan': None,
#            'full_name': 'Pool-0/' + UUID_2,
#            'userrefs': None,
#            'primarycache': 'all',
#            'logbias': 'latency',
#            'creation': '1591543140',
#            'sync': 'always',
#            'is_clone': False,
#            'dedup': 'off',
#            'sharenfs': None,
#            'receive_resume_token': None,
#            'volsize': '1073741824'}
#
#        self.start_patches(patches)
#
#        ret = jdssd.create_volume_from_snapshot(clone_vol, orig_snap)
#
#        jdssd.extend_volume.assert_not_called()
#        jdssd._clone_object.assert_called_once_with(origin_sname, clone_vname)
#        self.stop_patches(patches)
#
#        jdssd.ra.get_lun.assert_called_once_with(jcom.vname(clone_vol.id))
#        self.assertEqual(location, ret['provider_location'])
#        self.assertEqual(cred_format, ret['provider_auth'])
#
#    def test_create_cloned_volume_from_snapshot_extend(self):
#        jdssd, ctx = self.get_iscsi_driver(CONFIG_OK)
#
#        orig_snap = fake_snapshot.fake_snapshot_obj(ctx)
#        orig_snap.id = UUID_S1
#        orig_snap.volume_id = UUID_1
#
#        clone_vol = fake_volume.fake_volume_obj(ctx)
#        clone_vol.id = UUID_2
#        clone_vol.size = 2
#
#        host = CONFIG_OK["san_hosts"][0]
#        port = CONFIG_OK["target_port"]
#        target_name = CONFIG_OK["target_prefix"] + UUID_2
#
#        location = '{host}:{port},1 {name} 0'.format(
#            host=host,
#            port=port,
#            name=target_name
#        )
#
#        cred_format = (r"CHAP [0-9,a-z,A-Z]{{{name_len}}} "
#                       "[0-9,a-z,A-Z]{{{pass_len}}}").format(
#            name_len=8,
#            pass_len=CONFIG_OK['chap_password_len'])
#
#        patches = [
#            #mock.patch.object(jdssd, "_clone_object", return_value=None),
#            #mock.patch.object(jdssd, "extend_volume", return_value=None),
#            mock.patch.object(
#                jdssd,
#                "_get_provider_location",
#                return_value=location),
#            mock.patch.object(
#                jdssd,
#                "_get_provider_auth",
#                return_value=cred_format)]
#
#        #jdssd.ra.get_lun.return_value = {
#        #    'vscan': None,
#        #    'full_name': 'Pool-0/' + UUID_2,
#        #    'userrefs': None,
#        #    'primarycache': 'all',
#        #    'logbias': 'latency',
#        #    'creation': '1591543140',
#        #    'sync': 'always',
#        #    'is_clone': False,
#        #    'dedup': 'off',
#        #    'sharenfs': None,
#        #    'receive_resume_token': None,
#        #    'volsize': '1073741824'}
#
#        jdssd.driver.create_cloned_volume.return_value = None
#
#        self.start_patches(patches)
#
#        ret = jdssd.create_volume_from_snapshot(clone_vol, orig_snap)
#
#        jdssd.driver.create_cloned_volume.assert_called_once_with(
#                clone_vol.id,
#                orig_snap.volume_id,
#                clone_vol.size,
#                snapshot_name=orig_snap.id)
#        #jdssd.extend_volume.assert_called_once_with(clone_vol, clone_vol.size)
#        #jdssd._clone_object.assert_called_once_with(origin_sname, clone_vname)
#        self.stop_patches(patches)
#
#        #jdssd.ra.get_lun.assert_called_once_with(jcom.vname(clone_vol.id))
#        self.assertEqual(location, ret['provider_location'])
#        self.assertEqual(cred_format, ret['provider_auth'])
#
#    def test_clone_object(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#        origin = jcom.vname(UUID_1)
#        clone = jcom.vname(UUID_2)
#
#        jdssd.ra.create_snapshot.return_value = None
#        jdssd.ra.create_volume_from_snapshot.return_value = None
#
#        jdssd._clone_object(origin, clone)
#        jdssd.ra.create_snapshot.assert_called_once_with(origin, clone)
#        jdssd.ra.create_volume_from_snapshot.assert_called_once_with(
#            clone,
#            clone,
#            origin,
#            sparse=False)
#
#    def test_clone_object_dne(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#        calls = []
#        origin = jcom.vname(UUID_1)
#        clone = jcom.vname(UUID_2)
#        calls.append(mock.call(origin, clone))
#
#        jdssd.ra.create_snapshot.side_effect = (
#            jexc.JDSSResourceNotFoundException(res=origin))
#
#        self.assertRaises(exception.VolumeNotFound,
#                          jdssd._clone_object, origin, clone)
#
#        origin = jcom.sname(UUID_1)
#        calls.append(mock.call(origin, clone))
#
#        self.assertRaises(exception.SnapshotNotFound,
#                          jdssd._clone_object, origin, clone)
#        jdssd.ra.create_snapshot.assert_has_calls(calls)
#
#    def test_clone_object_exists(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#
#        origin = jcom.vname(UUID_1)
#        clone = jcom.vname(UUID_2)
#
#        jdssd.ra.create_snapshot.side_effect = (
#            jexc.JDSSSnapshotExistsException(snapshot=clone))
#
#        jdssd.ra.delete_snapshot.side_effect = (
#            jexc.JDSSSnapshotIsBusyException(snapshot=clone))
#
#        self.assertRaises(exception.Duplicate,
#                          jdssd._clone_object, origin, clone)
#        jdssd.ra.delete_snapshot.assert_called_once_with(origin, clone)
#        jdssd.ra.create_snapshot.assert_called_once_with(origin, clone)
#
#    def test_clone_object_volume_exists(self):
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#
#        origin = jcom.vname(UUID_1)
#        clone = jcom.vname(UUID_2)
#
#        jdssd.ra.create_snapshot.return_value = None
#        jdssd.ra.create_volume_from_snapshot.side_effect = (
#            jexc.JDSSVolumeExistsException(volume=clone))
#
#        self.assertRaises(exception.Duplicate,
#                          jdssd._clone_object, origin, clone)
#        jdssd.ra.create_snapshot.assert_called_once_with(origin, clone)
#        jdssd.ra.create_volume_from_snapshot.assert_called_once_with(
#            clone,
#            clone,
#            origin,
#            sparse=CONFIG_OK['san_thin_provision'])
#
#    def test_cascade_volume_delete_snapshot_clone(self):
#        # Volume with 3 snapshots and 1 clone of a snapshots
#        # We should delete childless snapshots
#        #           and then cal for volume deletion
#
#        jdssd, ctx = self.get_iscsi_driver(CONFIG_OK)
#        vol = fake_volume.fake_volume_obj(ctx)
#        vol.id = UUID_1
#        jdssd.driver.resize_volume.return_value = None
#        jdssd.extend_volume(vol, 2)
#
#        jdssd.driver.resize_volume.assert_called_once_with(
#            UUID_1, 2)
#
#        jdssd, ctx = self.get_driver(CONFIG_OK)
#        o_vname = jcom.vname(UUID_1)
#        o_snaps = SNAPSHOTS_CASCADE_1.copy()
#
#        jdssd.ra.modify_lun.return_value = None
#        jdssd.ra.delete_snapshot.return_value = None
#        jdssd.ra.get_snapshots.side_effect = [
#            SNAPSHOTS_EMPTY,
#            SNAPSHOTS_CASCADE_3.copy(),
#            SNAPSHOTS_EMPTY]
#        get_snapshots = [
#            mock.call(SNAPSHOTS_CASCADE_1[0]['name']),
#            mock.call(SNAPSHOTS_CASCADE_1[1]['name']),
#            mock.call(SNAPSHOTS_CASCADE_1[2]['name'])
#        ]
#        hide_object_expected = [
#            mock.call(SNAPSHOTS_CASCADE_1[1]["name"]),
#            mock.call(o_vname)]
#
#        #patches = [mock.patch.object(jdssd, "_gc_delete"),
#        #           mock.patch.object(jdssd, "_hide_object")]
#
#        #self.start_patches(patches)
#
#        #jdssd._cascade_volume_delete(o_vname, o_snaps)
#        #jdssd._hide_object.assert_has_calls(hide_object_expected)
#        #jdssd._gc_delete.assert_not_called()
#
#        #self.stop_patches(patches)
#
#        jdssd.ra.get_snapshots.assert_has_calls(get_snapshots)
#
#        delete_snapshot_expected = [
#            mock.call(o_vname,
#                      SNAPSHOTS_CASCADE_2[0]["name"],
#                      recursively_children=True,
#                      recursively_dependents=True,
#                      force_umount=True),
#            mock.call(o_vname,
#                      SNAPSHOTS_CASCADE_2[2]["name"],
#                      recursively_children=True,
#                      recursively_dependents=True,
#                      force_umount=True)]
#        jdssd.ra.delete_snapshot.assert_has_calls(delete_snapshot_expected)

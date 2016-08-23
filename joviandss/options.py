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

from oslo_config import cfg

JDSS_CONNECTION_OPTIONS = [
    cfg.StrOpt('jovian_host',
               default='',
               help='IP address of Open-E JovianDSS SA'),
    cfg.IntOpt('jovian_rest_port',
               default=80,
               help='HTTP port to connect to OpenE JovianDSS REST API server'),
    cfg.StrOpt('jovian_rest_protocol',
               default='https',
               choices=['http', 'https'],
               help='Use http or https for REST connection (default https)'),
    cfg.StrOpt('jovian_rest_send_repeats',
               default=3,
               help='Number of retries to send REST request.'),
    cfg.StrOpt('jovian_user',
               default='admin',
               help='User name to connect to Open-E JovianDSS SA'),
    cfg.StrOpt('jovian_password',
               default='password',
               help='Password to connect to Open-E JovianDSS SA',
               secret=True),
]

JDSS_ISCSI_OPTIONS = [
    cfg.IntOpt('jovian_iscsi_target_portal_port',
               default=3260,
               help='Open-E JovianDSS target portal port'),
    cfg.StrOpt('jovian_pool',
               default='Cinder-Pool-0',
               help='JovianDSS pool that holds all cinder volumes'),
    cfg.StrOpt('jovian_target_prefix',
               default='iqn.2016-04.com.open-e:01:cinder-',
               help='IQN prefix for iSCSI targets'),
    cfg.StrOpt('jovian_target_group_prefix',
               default='cinder/',
               help='Prefix for iSCSI target groups on Open-E JovianDSS SA'),
    cfg.StrOpt('jovian_chap_auth',
               default=False,
               help='Use CHAP authentication.'),
    cfg.StrOpt('jovian_chap_username',
               default='admin',
               help='CHAP user name for for iSCSI connection'),
    cfg.StrOpt('jovian_chap_pass_len',
               default=12,
               help='Length of the random string for CHAP password.'),

]

JDSS_VOLUME_OPTIONS = [
    cfg.StrOpt('jovian_blocksize',
               default='8KB',
               help='Block size for volumes (512B - 128KB)'),
    cfg.BoolOpt('jovian_sparse',
                default=False,
                help='Enables or disables the creation of sparse'
                     ' (thin-provisioned) volumes'),
]

CONF = cfg.CONF
CONF.register_opts(JDSS_CONNECTION_OPTIONS)
CONF.register_opts(JDSS_ISCSI_OPTIONS)
CONF.register_opts(JDSS_VOLUME_OPTIONS)

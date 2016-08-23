# -*- coding: utf-8 -*-
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

from cinder import exception
from oslo_log import log as logging
from cinder.volume.drivers import joviandss

from time import gmtime, strftime

LOG = logging.getLogger(__name__)

max_volume_name_size = 32


class JDSSRESTException(joviandss.JDSSException):
    pass


class JDSSRESTProxyException(joviandss.JDSSException):
    pass


class JDSSRESTResourceNotFoundException(joviandss.JDSSException):
    pass


def cinder_name_2_id(name_str):
    volume_prefix = "volume-"

    if len(volume_prefix) >= name_str or\
            volume_prefix != name_str[0:len(volume_prefix)]:

        LOG.error('Unexpected volume name {}.'.format(name_str))
        raise exception.VolumeDriverException("Unexpected volume name.")

    id_str = name_str[len(volume_prefix):]
    id_str = id_str.replace("-","")

    if len(id_str) > max_volume_name_size:
        LOG.error('Volume name is too large: {},'
                  ' must be less then: {} chars.'.format(
                    name_str,
                    max_volume_name_size))

        raise exception.VolumeDriverException("Unexpected volume name.")

    return id_str


def cinder_name_id_2_id(name_str):

    id_str = name_str.replace("-","")

    if len(id_str) > max_volume_name_size:

        LOG.error('Volume name is too large: {},'
                  ' must be less then: {} chars .'.format(
                    name_str,
                    max_volume_name_size))

        raise exception.VolumeDriverException("Unexpected volume name.")

    return id_str


def get_year_month():
    return strftime("%Y-%m", gmtime())


def get_jprefix():
    return "iqn.2015-05:"


def origin_snapshot(origin_str):
    return origin_str.split("@")[1]


def origin_volume(pool, origin_str):
    return origin_str.split("@")[0].split(pool + "/")[1]


class JDSSCommon(object):
    def __init__(self, conf, parent, context, db):
        self.configuration = conf
        self.generated_from = parent
        self.context = context
        self.db = db
        self.parent = parent

    def delete_snapshot(self, pool, volume, snapshot):

        LOG.debug('JovianDSS: delete snapshot {} for volume {}'.format(
            snapshot, volume))
        try:
            resp = self.parent.ra.delete_snapshot(self.parent.pool,
                                                  volume,
                                                  snapshot)
        except joviandss.JDSSException as exc:
            if "sanpshot is busy" == exc.args[0]:
                LOG.error('Failed to delete snapshot {}.'.format(
                    volume['name']))
                raise exception.SnapshotIsBusy(
                    data=('Failed to delete snapshot {1} of volume {2}.'.format(
                        snapshot, volume)))

        # TODO: implement volume detaching if it is based on particular snapshot

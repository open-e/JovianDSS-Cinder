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

"""Common resources for JovianDSS driver."""
max_volume_name_size = 96

def vname(name):
    """Convert id into volume name"""

    if name[:2] == 'v_':
        return name
    
    if name[:2] == 's_':
        msg = _('Attempt to use snapshot %s as a volume') % name
        raise exception.VolumeBackendAPIException(message=msg)

    if name[:2] == 't_':
        msg = _('Attempt to use deleted object %s as a volume') % name
        raise exception.VolumeBackendAPIException(message=msg)

    return 'v_' + name

def sname(name):
    """Convert id into snapshot name"""

    if name[:2] == 's_':
        return name

    if name[:2] == 'v_':
        msg = _('Attempt to use volume %s as a snapshot') % name
        raise exception.VolumeBackendAPIException(message=msg)

    if name[:2] == 't_':
        msg = _('Attempt to use deleted object %s as a snapshot') % name
        raise exception.VolumeBackendAPIException(message=msg)

    return 's_' + name

def is_hidden(name):
    """Check if object is active or no"""

    if len(name) < 2:
        return False
    if name[:2] == 't_':
        return True
    return False

def origin_snapshot(origin_str):
    """Extracts original phisical snapshot name from origin record"""

    return origin_str.split("@")[1]

def origin_volume(pool, origin_str):
    """Extracts original phisical volume name from origin record"""

    return origin_str.split("@")[0].split(pool + "/")[1]

def full_name_volume(name):
    return name.split('/')[1]

def hidden(name):
    if len(name) < 2:
        return ''
    if name[:2] == 'v_' || name[:2] == 's_':
        return 't_' + name[2:]

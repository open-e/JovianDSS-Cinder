# Open-E JovianDSS driver for Cinder

## Description

This repository contains source files for the JovianDSS Cinder volume driver.

## Installation


### Get source code

```bash
git clone https://github.com/Open-E/JovianDSS-Cinder
```

Copy __*open_e*__ folder to your Cinder driver folder.
For instance if your Cinder is located at __*/opt/stack/cinder/*__, the command will looks like:

```bash
cp -R JovianDSS-Cinder/joviandss /opt/stack/cinder/cinder/volume/drivers/open_e
```


### Configuring

Edit with your favorite editor Cinder config file. 
It can be found at /etc/cinder/cinder.conf

Add the field enabled\_backends with value joviandss:

```
enabled_backends=jdss-0
```
Provide settings to JovianDSS driver by adding 'jdss-0' description:

```
[jdss-0]
volume_backend_name=jdss-0
chap_password_len=14
driver_use_ssl=True
iscsi_target_prefix=iqn.2016-04.com.open-e.cinder:
jovian_pool=Pool-0
jovian_block_size=64K
jovian_rest_send_repeats=4
san_api_port=82
target_port=3260
volume_driver=cinder.volume.drivers.open_e.iscsi.JovianISCSIDriver
san_hosts=192.168.0.40
san_login=admin
san_password=admin
san_thin_provision=True
```
	

**Open-E JovianDSS configuration options**

| Option                     | Default value                     | Description                                                         |
|----------------------------|-----------------------------------|---------------------------------------------------------------------|
| `volume_backend_name`      | JovianDSS-iSCSI                   | Name of the back end                                                |
| `chap_password_len`        | 12                                | Length of the unique generated CHAP password.                       |
| `driver_use_ssl`           | True                              | Use SSL to send requests to JovianDSS\[1\]                          |
| `iscsi_target_prefix`      | iqn.2016-04.com.open-e:01:cinder- | Prefix that will be used to form target name for volume             |
| `jovian_pool`              | Pool-0                            | Pool name that is going to be used. Must be created in \[2\]        |
| `jovian_block_size`        | 64K                               | Block size for new volume, can be: 32K, 64K, 128K, 256K, 512K, 1M   |
| `jovian_rest_send_repeats` | 3                                 | Number of times that driver will try to send REST request           |
| `san_api_port`             | 82                                | Rest port according to the settings in \[1\]                        |
| `target_port`              | 3260                              | Port for iSCSI connections                                          |
| `volume_driver`            |                                   | Location of the driver source code                                  |
| `san_hosts`                |                                   | Comma separated list of IP address of the JovianDSS                 |
| `san_login`                | admin                             | Must be set according to the settings in \[1\]                      |
| `san_password`             | admin                             | Jovian password \[1\], **should be changed** for security purpouses |
| `san_thin_provision`       | False                             | Using thin provisioning for new volumes                             |


[1] Can be enabled by going to JovianDSS Web interface/System Settings/REST Access

[2] [Can be created by going to JovianDSS Web interface/Storage](https://www.open-e.com/site_media/download/documents/Open-E-JovianDSS-Advanced-Metro-High-Avability-Cluster-Step-by-Step-2rings.pdf)

[More info about Open-E JovianDSS](http://blog.open-e.com/?s=how+to)

### Run

Now you should restart Cinder service.

Create new volume type according to the back end name provided previously:

```bash
$ cinder type-create jdss-0
```

Response would be(ID is unique ID, you will have different value):
```
+--------------------------------------+-----------+-------------+-----------+
|                  ID                  |    Name   | Description | Is_Public |
+--------------------------------------+-----------+-------------+-----------+
| 70f92fa6-200d-42cf-b132-cbbd3d9c71a4 |   jdss-0  |      -      |    True   |
+--------------------------------------+-----------+-------------+-----------+
```

Check the list of available types
```bash
$ cinder type-list
```

Response would be like:
```
+--------------------------------------+-------------+-------------+-----------+
|                  ID                  |     Name    | Description | Is_Public |
+--------------------------------------+-------------+-------------+-----------+
| 07a842ea-543c-455b-9688-327673a7b001 | lvmdriver-1 |      -      |    True   |
| 70f92fa6-200d-42cf-b132-cbbd3d9c71a4 |    jdss-0   |      -      |    True   |
+--------------------------------------+-------------+-------------+-----------+
```

Now try to create volume:


```bash
$ cinder create --name my_test_volume --volume-type jdss-0 1
```

Response would be like:
```
+--------------------------------+--------------------------------------+
|            Property            |                Value                 |
+--------------------------------+--------------------------------------+
|          attachments           |                  []                  |
|       availability_zone        |                 nova                 |
|            bootable            |                false                 |
|      consistencygroup_id       |                 None                 |
|           created_at           |      2016-08-23T12:27:28.000000      |
|          description           |                 None                 |
|           encrypted            |                False                 |
|               id               | 9720999d-d1e1-4700-9ac1-5348b823acfc |
|            metadata            |                  {}                  |
|        migration_status        |                 None                 |
|          multiattach           |                False                 |
|              name              |            my_test_volume            |
|     os-vol-host-attr:host      |    ubuntu@joviandss#Jovian_iSCSI     |
| os-vol-mig-status-attr:migstat |                 None                 |
| os-vol-mig-status-attr:name_id |                 None                 |
|  os-vol-tenant-attr:tenant_id  |   2ad05ea0a7de464c9d50a2fdaba1b526   |
|       replication_status       |               disabled               |
|              size              |                  1                   |
|          snapshot_id           |                 None                 |
|          source_volid          |                 None                 |
|             status             |               creating               |
|           updated_at           |      2016-08-23T12:27:29.000000      |
|            user_id             |   c4f4dd53f8b649edaa294090b3c2c81e   |
|          volume_type           |              joviandss               |
+--------------------------------+--------------------------------------+
```

Now if you go to the JovianDSS Web interface you will see volume with name:
```
9720999dd1e147009ac15348b823acfc
```

### Multiple Pools

All you need to add another JovianDSS Pool is to create a copy of JovianDSS config in cinder.conf file.

For instance if you want to add `Pool-1` located on the same host as `Pool-0`.
You extend `cinder.conf` file like:

```
enabled_backends = jdss-0, jdss-1

[jdss-0]
volume_backend_name=jdss-0
chap_password_len=14
driver_use_ssl=True
iscsi_target_prefix=iqn.2016-04.com.open-e.cinder:
jovian_pool=Pool-0
jovian_block_size=64K
jovian_rest_send_repeats=4
san_api_port=82
target_port=3260
volume_driver=cinder.volume.drivers.open_e.iscsi.JovianISCSIDriver
san_hosts=192.168.0.40
san_login=admin
san_password=admin
san_thin_provision=True

[jdss-1]
volume_backend_name=jdss-1
chap_password_len=14
driver_use_ssl=True
iscsi_target_prefix=iqn.2016-04.com.open-e.cinder:
jovian_pool=Pool-1
jovian_block_size=64K
jovian_rest_send_repeats=4
san_api_port=82
target_port=3260
volume_driver=cinder.volume.drivers.open_e.iscsi.JovianISCSIDriver
san_hosts=192.168.0.50
san_login=admin
san_password=admin
san_thin_provision=True
```
Do not forget to change values of `jovian_pool` and `volume_backend_name `. Everything else remain the same.

### HA Cluster

To utilize High Availability feature of of JovianDSS:
1. [Configure Pool to high availability cluster](https://www.youtube.com/watch?v=juWIQT_bAfM)
2. Set `jovian_hosts` with list of `virtual IPs` associated with this Pool

For instance if you have `Pool-2` with 2 virtual IPs 192.168.21.100 and 192.168.31.100 the configuration file will look like:
```
[jdss-2]

volume_backend_name=jdss-2
chap_password_len=14
driver_use_ssl=True
iscsi_target_prefix=iqn.2016-04.com.open-e.cinder:
jovian_pool=Pool-0
jovian_block_size=64K
jovian_rest_send_repeats=4
san_api_port=82
target_port=3260
volume_driver=cinder.volume.drivers.open_e.iscsi.JovianISCSIDriver
san_hosts=192.168.21.100, 192.168.31.100
san_login=admin
san_password=admin
san_thin_provision=True
```

## License

    Copyright (c) 2016 Open-E, Inc.
    All Rights Reserved.

    Licensed under the Apache License, Version 2.0 (the "License"); you may
    not use this file except in compliance with the License. You may obtain
    a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
    License for the specific language governing permissions and limitations
    under the License.

## Feedback

Please address problems and proposals to andrei.perepiolkin@open-e.com

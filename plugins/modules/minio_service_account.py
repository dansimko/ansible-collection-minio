#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: Daniel Simko <daniel@simko.xyz>, Josh Williams <jdubz@dubzland.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: minio_service_account
short_description: Manages Minio service accounts
description:
  - When the service account does not exist, it will be created.
  - When the service account does exist and O(state=absent), the service account will be deleted.
  - When changes are made to the service account, the service account will be updated.
author:
  - Josh Williams (@t3hpr1m3)
  - Daniel Simko (@dansimko)
requirements:
  - python >= 3.8
  - minio >= 7.1.4
attributes:
  check_mode:
    support: full
    description: Can run in check_mode and return changed status prediction without modifying target.
  diff_mode:
    support: none
    description: Will return details on what has changed (or possibly needs changing in check_mode), when in diff mode.
options:
  access_key:
    type: str
    required: true
    description: Access key for the service account.
  secret_key:
    type: str
    required: true
    description: Secret key for the service account.
  name:
    type: str
    required: false
    description: Human-readable name for the service account.
  description:
    type: str
    required: false
    description: Description for the service account.
  policy:
    type: dict
    required: false
    description: Policy to attach to the service account.
  expiration:
    type: str
    required: false
    description: Expiration date for the service account. For allowed formats see the B(mc admin user svcacct add) command.
  state:
    description:
      - Indicates the desired service account state.
      - V(present) ensures the service account is present.
      - V(absent) ensures the service account is absent.
      - V(enabled) ensures the service account is enabled.
      - V(disabled) ensures the service account is disabled.
    default: present
    choices: [ "present", "absent", "enabled", "disabled" ]
    type: str
seealso:
  - name: mc mb
    description: Documentation for the B(mc admin user svcacct) command.
    link: https://min.io/docs/minio/linux/reference/minio-mc-admin/mc-admin-user-svcacct.html
extends_documentation_fragment: dubzland.minio.minio_auth
"""

EXAMPLES = """
- name: Add a Minio service account
  dubzland.minio.minio_service_account:
    access_key: testsvcacct
    secret_key: supersekret
    name: Test service account
    policy:
      Version: "2012-10-17"
      Statement:
        - Effect: Allow
          Action:
            - "s3:*"
          Resource:
            - "arn:aws:s3:::testbucket"
            - "arn:aws:s3:::testbucket/*"
    auth:
      access_key: minioadmin
      secret_key: minioadmin
      url: http://minio-server:9000
    state: present
  delegate_to: localhost
"""

import json
import tempfile

from minio.error import MinioAdminException

from ansible_collections.dubzland.minio.plugins.module_utils.minio import (
    minio_admin_client,
    minio_argument_spec,
)

from ansible.module_utils.basic import AnsibleModule


class MinioServiceAccount:
    def __init__(self, module, minio_client):
        self._module = module
        self._client = minio_client
        self.service_account_object = None

    def find_service_account(self, access_key):
        try:
            service_account_obj_str = self._client.get_service_account(access_key)
            service_account_obj = json.loads(service_account_obj_str)
        except MinioAdminException as exc:
            # If we got 404, access key not found
            if exc._code != "404":
                raise exc

            service_account_obj = None

        return service_account_obj

    def service_account_exists(self, access_key):
        service_account = self.find_service_account(access_key)
        if service_account:
            self.service_account_object = service_account
            return True

        return False

    def create_or_update_service_account(self, access_key, secret_key, name=None, description=None, policy=None,
                                         expiration=None, state=None):
        changed = False

        if state == "present":
            state = None

        state = state if state in {"enabled", "disabled"} else None

        # Construct service account options
        svcacct_options = {
            "access_key": access_key,
            "secret_key": secret_key,
            "name": name,
            "description": description,
            "expiration": expiration,
            "status": state
        }
        fp = None

        if policy:
            # Dump the policy into a file for the MinIO client
            fp = tempfile.NamedTemporaryFile("w", delete_on_close=False)
            json.dump(policy, fp)
            fp.close()

            svcacct_options["policy_file"] = fp.name

        if self.service_account_object is None:
            if self._module.check_mode:
                return True

            # This may raise on conflict of access_key if a different user already has a service account with the same
            # access_key.
            self._client.add_service_account(**svcacct_options)
            self.service_account_object = self._client.get_service_account(access_key)
            changed = True
        else:
            previous_state = self.service_account_object

            self._client.update_service_account(**svcacct_options)
            self.service_account_object = self._client.get_service_account(access_key)

            changed = previous_state != self.service_account_object

        if fp is not None:
            # Cleanup the temporary file
            fp.__exit__(None, None, None)

        return changed

    def delete_service_account(self, access_key):
        self._client.delete_service_account(access_key)
        
        return True


def main():
    argument_spec = minio_argument_spec(
        access_key=dict(type="str", required=True, no_log=True),
        secret_key=dict(type="str", required=True, no_log=True),
        name=dict(type="str", required=False, default=None),
        description=dict(type="str", required=False, default=None),
        policy=dict(type="dict", required=False, default=None),
        expiration=dict(type="str", required=False, default=None),
        state=dict(
            default="present", choices=["present", "absent", "enabled", "disabled"]
        ),
    )
    module = AnsibleModule(argument_spec=argument_spec, supports_check_mode=True)

    access_key = module.params["access_key"]
    secret_key = module.params["secret_key"]
    name = module.params["name"]
    description = module.params["description"]
    policy = module.params["policy"]
    expiration = module.params["expiration"]
    state = module.params["state"]

    changed = False

    client = minio_admin_client(module)

    minio_service_account = MinioServiceAccount(module, client)

    exists = minio_service_account.service_account_exists(access_key)

    if state != "absent":
        changed = minio_service_account.create_or_update_service_account(
            access_key=access_key,
            secret_key=secret_key,
            name=name,
            description=description,
            policy=policy,
            expiration=expiration,
            state=state
        )
    else:
        if exists:
            changed = minio_service_account.delete_service_account(access_key)

    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()

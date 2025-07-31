# -*- coding: utf-8 -*-

# Copyright: Daniel Simko <daniel@simko.com>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = """
options: {}
attributes:
  action_group:
    description: Use C(group/dubzland.minio.minio) in C(module_defaults) to set defaults for this module.
    support: full
    membership:
      - dubzland.minio.minio
"""


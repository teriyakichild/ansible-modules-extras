#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Tony Rogers (@teriyakichild)
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.
#

DOCUMENTATION = '''
---
module: zabbix_template
short_description: Zabbix template creates/updates/deletes
description:
   - This module allows you to create, modify and delete Zabbix template and associate group and link other templates.
version_added: "2.0"
author: 
    - "Tony Rogers (@teriyakichild)"
requirements:
    - "python >= 2.7"
    - pyzabbix
options:
    server_url:
        description:
            - Url of Zabbix server, with protocol (http or https).
        required: true
        aliases: [ "url" ]
    login_user:
        description:
            - Zabbix user name, used to authenticate against the server.
        required: true
    login_password:
        description:
            - Zabbix user password.
        required: true
    verify_ssl:
        description:
            - Whether or not we want to verify the ssl of server_url.
        required: false
	default: True
    template_name:
        description:
            - Name of the template in Zabbix.
            - template_name is the unique identifier used and cannot be updated.
        required: true
    host_groups:
        description:
            - List of host groups the template is part of.
        required: false
        default: ["Templates"]
    link_templates:
        description:
            - List of templates linked to the template.
        required: false
        default: []
    state:
        description:
            - State of the host.
            - On C(present), it will create if template does not exist or update the template if the associated data is different.
            - On C(absent) will remove the template if it exists.
        required: false
        choices: ['present', 'absent']
        default: "present"
'''

EXAMPLES = '''
- name: Create a new template or update an existing template's info
  local_action:
    module: zabbix_template
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    template_name: Template Name
    host_groups:
      - Example group1
      - Example group2
    link_templates:
      - Example template1
      - Example template2
    state: present

- name: Create a new template or update an existing template's info
  local_action:
    module: zabbix_template
    server_url: http://monitor.example.com
    login_user: username
    login_password: password
    verify_ssl: False
    template_name: Template Name
    host_groups:
      - Example group1
      - Example group2
    link_templates:
      - Example template1
      - Example template2
    state: absent
'''

import logging
import copy

try:
#    from zabbix_api import ZabbixAPI, ZabbixAPISubClass
    from pyzabbix import ZabbixAPI, ZabbixAPIException

    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False


class Template(object):
    def __init__(self, module, zbx):
        self._module = module
        self._zapi = zbx

    # exist template
    def is_template_exist(self, template_name):
        result = self._zapi.template.exists(**{'host': template_name})
        return result

    # check if host group exists
    def check_host_group_exist(self, group_names):
        for group_name in group_names:
            result = self._zapi.hostgroup.exists(**{'name': group_name})
            if not result:
                self._module.fail_json(msg="Hostgroup not found: %s" % group_name)
        return True

    def get_template_ids(self, template_list):
        template_ids = []
        if template_list is None or len(template_list) == 0:
            return template_ids
        for template in template_list:
            template_list = self._zapi.template.get(**{'output': 'extend', 'filter': {'host': template}})
            if len(template_list) < 1:
                self._module.fail_json(msg="Template not found: %s" % template)
            else:
                template_id = template_list[0]['templateid']
                template_ids.append(template_id)
        return template_ids

    def add_template(self, template_name, group_ids, link_templates):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            parameters = {'host': template_name, 'groups': group_ids, 'templates': link_templates}
            template_list = self._zapi.template.create(**parameters)
            if len(template_list) >= 1:
                return template_list['templateids'][0]
        except Exception, e:
            self._module.fail_json(msg="Failed to create template %s: %s" % (template_name, e))

    def update_template(self, template_id, template_name, group_ids, link_templates):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            parameters = {'templateid': template_id, 'groups': group_ids, 'templates': link_templates}
            self._zapi.template.update(**parameters)
        except Exception, e:
            self._module.fail_json(msg="Failed to update template %s: %s" % (template_name, e))

    def delete_template(self, template_id, template_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.template.delete(*[template_id])
        except Exception, e:
            self._module.fail_json(msg="Failed to delete template %s: %s" % (template_name, e))

    # get template by template name
    def get_template_by_template_name(self, template_name):
        template_list = self._zapi.template.get(**{'output': 'extend', 'filter': {'host': [template_name]}})
        if len(template_list) < 1:
            self._module.fail_json(msg="Template not found: %s" % template_name)
        else:
            return template_list[0]

    # get group ids by group names
    def get_group_ids_by_group_names(self, group_names):
        group_ids = []
        if self.check_host_group_exist(group_names):
            group_list = self._zapi.hostgroup.get(**{'output': 'extend', 'filter': {'name': group_names}})
            for group in group_list:
                group_id = group['groupid']
                group_ids.append({'groupid': group_id})
        return group_ids

    # get host templates by host id
    def get_host_templates_by_host_id(self, host_id):
        template_ids = []
        template_list = self._zapi.template.get(**{'output': 'extend', 'hostids': host_id})
        for template in template_list:
            template_ids.append(template['templateid'])
        return template_ids

    # get host groups by host id
    def get_host_groups_by_template_id(self, template_id):
        exist_host_groups = []
        host_groups_list = self._zapi.hostgroup.get(**{'output': 'extend', 'templateids': template_id})
        print template_id
        if len(host_groups_list) >= 1:
	    print host_groups_list
            for host_groups_name in host_groups_list:
                exist_host_groups.append(host_groups_name['name'])
        return exist_host_groups

    def check_all_properties(self, template_id, host_groups, template_ids):
        # get the existing host's groups
        exist_host_groups = self.get_host_groups_by_template_id(template_id)
        if set(host_groups) != set(exist_host_groups):
            return True

        # get the existing templates
        exist_template_ids = self.get_host_templates_by_host_id(template_id)
        if set(list(template_ids)) != set(exist_template_ids):
            return True

        return False


def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_url=dict(required=True, aliases=['url']),
            login_user=dict(required=True),
            login_password=dict(required=True, no_log=True),
	    verify_ssl=dict(required=False, default=True),
            template_name=dict(required=True),
            host_groups=dict(required=False, default=["Templates"]),
            link_templates=dict(required=False),
            state=dict(default="present", choices=['present', 'absent']),
        ),
        supports_check_mode=True
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg="Missing required pyzabbix module (check docs or install with: pip install pyzabbix)")

    server_url = module.params['server_url']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    verify_ssl = module.params['verify_ssl']
    template_name = module.params['template_name']
    host_groups = module.params['host_groups']
    link_templates = module.params['link_templates']
    state = module.params['state']

    zbx = None
    # login to zabbix
    try:
        zbx = ZabbixAPI(server_url)
        zbx.session.verify = verify_ssl
        zbx.login(login_user, login_password)
    except Exception, e:
        module.fail_json(msg="Failed to connect to Zabbix server: %s" % e)

    template = Template(module, zbx)

    template_ids = []
    if link_templates:
        template_ids = template.get_template_ids(link_templates)

    group_ids = []

    if host_groups:
        group_ids = template.get_group_ids_by_group_names(host_groups)

    # check if template exist
    is_template_exist = template.is_template_exist(template_name)
    print is_template_exist

    if is_template_exist:
	print 'exists'
        # get template id by template name
        zabbix_host_obj = template.get_template_by_template_name(template_name)
        template_id = zabbix_host_obj['templateid']

        if state == "absent":
            # remove template
            template.delete_template(template_id, template_name)
            module.exit_json(changed=True, result="Successfully deleted template %s (%s)" % (template_name, template_id))
        else:
            if template.check_all_properties(template_name, host_groups, template_ids):
                template.update_template(template_id, template_name, group_ids, template_ids)
                module.exit_json(changed=True,
                                 result="Successfully update template %s (%s) and linked with templates '%s' and hostgroups '%s'"
                                 % (template_name, template_id, link_templates, host_groups))
            else:
                module.exit_json(changed=False)
    else:
        # create host
        template_id = template.add_template(template_name, group_ids, template_ids)
        module.exit_json(changed=True, result="Successfully added template %s (%s) and linked with template '%s' and in '%s' hostgroups" % (
            template_name, template_id, link_templates, host_groups))

from ansible.module_utils.basic import *
main()


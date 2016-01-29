#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Tony Rogers <tony@tonyrogers.me>
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
module: zabbix_api
short_description: Interact with the zabbix api
description:
    - This module allows you to interact with the zabbix api.  You can call
    - any method and supply the arguments.
version_added: "2.0"
author:
    - "Tony Rogers"
requirements:
    - "python >= 2.6"
    - pyzabbix
options:
    server_url:
        description:
            - Url of Zabbix server, with protocol (http or https).
        required: true
        aliases: [ "url" ]
    login_user:
        description:
            - Zabbix user name.
        required: true
    login_password:
        description:
            - Zabbix user password.
        required: true
    ssl_verify:
        description:
            - Whether or not to verify the SSL certificate
        type: bool
        default: true
    timeout:
        description:
            - The timeout of API request (seconds).
        default: 10
    method:
        description:
            - The API method we are going to call.
        required: true
    arguments:
        description:
            - List of arguments to send to the api
        required: true
    fact_name:
        description:
            - The name of the fact that will contain the response from zabbix
        default: zabbix_response
'''

EXAMPLES = '''
# Create a user.
- name: Create user
  local_action:
    module: zabbix_api
    server_url: http://zabbix.example.com
    login_user: username
    login_password: password
    method: user.create
    arguments:
      alias: username
      usrgrps:
        - usrgrpid: 7
      passwd: ""
      type: 3

# Create an action.
- name: Create Action
  local_action:
    module: zabbix_api
    server_url: http://zabbix.example.com
    login_user: username
    login_password: password
    method: action.create
    arguments:
      eventsource: 2
      status: 0
      esc_period: 0
      evaltype: 0
      conditions:
        - conditiontype: 24
          value: 2b335fv0-2a5b-dse4-fa2a-gxw52b0cxa6q
          operator: 2
      operations:
        - operationtype: 6
          esc_period: 0
          evaltype:0
          opconditions: []
          esc_step_to: 1
          esc_step_from: 1
          optemplate:
            - templateid: 10101
              operationid: 4
      def_shortdata: "Auto registration: {HOST.HOST}"
      def_longdata: "Host name: {HOST.HOST}\r\nHost IP: {HOST.IP}\r\nAgent port: {HOST.PORT}"
      name: "Auto Registration (Active)"

  - name: Create Host Group
    local_action:
      module: zabbix_api
      server_url: https://zabbix.example.com
      login_user: username
      login_password: password
      ssl_verify: true
      method: hostgroup.create
      arguments:
        name: New Hostgroup

# Create a global macro.
- name: Create global macro
  local_action:
    module: zabbix_api
    server_url: http://zabbix.example.com
    login_user: username
    login_password: password
    method: usermacro.createglobal
    arguments:
      macro: "{$SERVER_URL}"
      value: http://zabbix.example.com

# Create a host.
- name: Create Host
  local_action:
    module: zabbix_api
    server_url: http://zabbix.example.com
    login_user: username
    login_password: password
    method: host.create
    arguments:
      host: node.example.com
      interfaces:
        - type: 1
          main: 1
          useip: 0
          ip: ""
          dns: node.example.com
          port: 10050
      groups:
        - groupid: 10
      templates:
        - templateid: 10170
'''

try:
    from pyzabbix import ZabbixAPI, ZabbixAPIException
    HAS_ZABBIX_API = True
except ImportError:
    HAS_ZABBIX_API = False

### MY STUFF STARTS HERE ###
class Zabbix(object):
    STATUS = True
    ERROR = None

    def __init__(self, server_url, module, timeout=10, ssl_verify=True):
        self._module = module
        self.zapi = ZabbixAPI(server_url)
        self.zapi.session.verify = ssl_verify
        self.zapi.timeout = timeout

    def auth(self, username, password):
        try:
            self.zapi.login(username, password)
            self.ERROR = None
            self.STATUS = True
        except ZabbixAPIException as e:
            self.ERROR = e
            self.STATUS = False
            return False
        return True

    def call_api(self, method, arguments):
        parts = self._split_method(method)
        func = getattr(getattr(self.zapi, parts[0]), parts[1])
        if type(arguments) == str or type(arguments) == int:
            return func(str(arguments))
        elif type(arguments) == list:
            return func(*arguments)
        else:
            return func(**arguments)

    def find_resource(self, method, resource):
        parts = self._split_method(method)
        # list of keys with which to search the api.  We will use the first key that exists
        # in the resource parameter
        keys = ['alias', 'macro', 'host', 'name']
        unique_key = 'name'
        for key in keys:
            if resource.get(key, False):
                unique_key = key
                break
        filter_query = {unique_key: resource.get(unique_key)}

        # Some resource types require additional parameters in the get() call.
        extra_params = {}
        if parts[1] == 'createglobal':
            extra_params['globalmacro'] = True

        ret = getattr(self.zapi, parts[0]).get(
                filter=filter_query,
                **extra_params
            ) 
        if len(ret) == 1:
            return ret
        else:
            raise Exception('Wrong number of resources found')

    def _split_method(self, method):
        parts = method.split('.')
        if len(parts) != 2:
            raise Exception('The "method" argument is not valid')
        return parts


def main():
    module = AnsibleModule(
        argument_spec=dict(
            server_url=dict(required=True, aliases=['url']),
            login_user=dict(required=True),
            login_password=dict(required=True, no_log=True),
            ssl_verify=dict(default=True, type='bool'),
            timeout=dict(type='int', default=10),
            method=dict(required=True),
            arguments=dict(type='dict', required=True),
            fact_name=dict(required=False, default='zabbix_response')
        )
    )

    if not HAS_ZABBIX_API:
        module.fail_json(msg="Missing requried pyzabbix module (check docs or install with: pip install pyzabbix)")

    server_url = module.params['server_url']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    ssl_verify = module.params['ssl_verify']
    timeout = module.params['timeout']
    method = module.params['method']
    arguments = module.params['arguments']
    fact_name = module.params['fact_name']

    zbx = Zabbix(server_url, module, timeout=timeout, ssl_verify=ssl_verify)
    zbx.auth(login_user, login_password)
    if not zbx.STATUS:
        module.fail_json(msg="Failed to connect to Zabbix server: %s" % zbx.ERROR)
    try:
        results = zbx.call_api(method, arguments)
        module.exit_json(ansible_facts={fact_name: results}, changed=True, msg=results)
    except Exception as e:
        if 'already exists' in str(e):
            results = zbx.find_resource(method, arguments)
            module.exit_json(ansible_facts={fact_name: results}, changed=False, msg=str(e))
        else:
            module.fail_json(msg={'error': str(e)})

from ansible.module_utils.basic import *

if __name__ == '__main__':
    main()

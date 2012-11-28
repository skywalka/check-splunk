#!/usr/bin/env python

from xml.dom import minidom

import pynagios
import urllib
import urllib2
import time

default_splunk_opts = {
    'index_name': 'main',
    'license_pool': 'auto_generated_pool_enterprise',
}

class SplunkServer(object):
    urls = {
        'LOGIN': '/services/auth/login',
        'INDEX_LIST': '/services/data/indexes',
        'INDEX_INFO': '/servicesNS/nobody/system/data/indexes/%(index_name)s',
        'LICENSE_LIST': '/services/licenser/licenses',
        'LICENSE_POOL': '/servicesNS/nobody/system/licenser/pools/%(license_pool)s',
        'LICENSE_INFO': '/servicesNS/nobody/system/licenser/licenses/%(license_hash)s',
        'SERVER_INFO': '/servicesNS/nobody/system/server/info',
    }

    def __init__(self, server, username, password, port=8089, **kwargs):
        self.server = server
        self.username = username
        self.password = password
        self.port = int(port)

        self.splunk_vals = dict()
        self.splunk_vals.update(default_splunk_opts)
        self.splunk_vals.update(kwargs)

        self._authtoken = self.login()

    def _build_url(self, urlkey):
        url = self.urls[urlkey] % self.splunk_vals
        return 'https://%s:%d%s' % (self.server, self.port, url)

    def _url_get(self, urlkey, data=None, login=False, raw=False):
        k = urlkey.upper()

        if not login:
            headers = {
                'Authorization': 'Splunk %s' % self.authtoken
            }
        else:
            headers = dict()

        if data is not None:
            _data = urllib.urlencode(data)
        else:
            _data = None

        req = urllib2.Request(self._build_url(k), _data, headers)
        response = urllib2.urlopen(req)
        if raw:
            return response
        else:
            return minidom.parseString(response.read())

    def login(self):
        data = { 'username': self.username, 'password': self.password }
        response = self._url_get('LOGIN', data, login=True)

        self._server_info = None
        self._licenses = None
        self._pool_info = None

        return response.getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue

    @property
    def authtoken(self):
        if self._authtoken is None:
            self._authtoken = self.login()
        return self._authtoken

    @property
    def current_db_size(self):
        db_info = self._url_get('INDEX_INFO')
        key_nodes = db_info.getElementsByTagName('s:key')
        nodes = filter(lambda node: node.attributes['name'].value == 'currentDBSizeMB', key_nodes)
        return int(nodes[0].firstChild.nodeValue)

    @property
    def max_db_size(self):
        db_info = self._url_get('INDEX_INFO')
        key_nodes = db_info.getElementsByTagName('s:key')
        nodes = filter(lambda node: node.attributes['name'].value == 'maxTotalDataSizeMB', key_nodes)
        return int(nodes[0].firstChild.nodeValue)

    @property
    def isTrial(self):
        if self._server_info == None:
            self._server_info = self._url_get('SERVER_INFO')
        key_nodes = self._server_info.getElementsByTagName('s:key')
        nodes = filter(lambda node: node.attributes['name'].value == 'isTrial', key_nodes)
        if nodes[0].firstChild.nodeValue == '0':
            return False
        else:
            return True

    @property
    def isFree(self):
        if self._server_info == None:
            self._server_info = self._url_get('SERVER_INFO')
        key_nodes = self._server_info.getElementsByTagName('s:key')
        nodes = filter(lambda node: node.attributes['name'].value == 'isFree', key_nodes)
        if nodes[0].firstChild.nodeValue == '0':
            return False
        else:
            return True

    def _get_license_data(self, entry):
        hash = entry.getElementsByTagName('title')[0].childNodes[0].nodeValue
        if hash[:-1] == 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF':
            return None
        dobj = entry.getElementsByTagName('s:dict')[0]
        l = dict()
        for data in dobj.getElementsByTagName('s:key'):
            if data.parentNode != dobj:
                continue
            key = data.attributes['name'].value
            if data.firstChild is None:
                value = ""
            elif data.firstChild.nodeType == 1:
                # Not a text node
                container = data.firstChild
                if container.tagName == "s:dict":
                    value = dict()
                    for node in container.childNodes:
                        k = node.attributes['name'].value
                        if node.firstChild is None:
                            value[k] = ""
                        else:
                            value[k] = node.firstChild.nodeValue
                elif container.tagName == "s:list":
                    value = list()
                    for node in container.childNodes:
                        if node.firstChild is None:
                            value.append("")
                        else:
                            value.append(node.firstChild.nodeValue)
            else:
                value = data.firstChild.nodeValue
            l[key] = value
        return (hash, l)

    @property
    def licenses(self):
        if self._licenses is None:
            self._licenses = self._url_get('LICENSE_LIST')
        
        lic_data = map(self._get_license_data, self._licenses.getElementsByTagName('entry'))
        lic_data = filter(lambda x: x is not None, lic_data)
        return dict(lic_data)

    @property
    def license_expiration_time(self):
        license_info = self._url_get('LICENSE_INFO')
        key_nodes = license_info.getElementsByTagName('s:key')
        nodes = filter(lambda node: node.attributes['name'].value == 'expiration_time', key_nodes)
        return int(nodes[0].firstChild.nodeValue)

    def _get_pool_data(self, entry):
        dobj = entry.getElementsByTagName('s:dict')[0]
        p = dict()
        for data in dobj.getElementsByTagName('s:key'):
            if data.parentNode != dobj:
                continue
            key = data.attributes['name'].value
            if data.firstChild is None:
                value = ""
            elif data.firstChild.nodeType == 1:
                # Not a text node
                container = data.firstChild
                if container.tagName == "s:dict":
                    value = dict()
                    for node in container.childNodes:
                        k = node.attributes['name'].value
                        if node.firstChild is None:
                            value[k] = ""
                        else:
                            value[k] = node.firstChild.nodeValue
                elif container.tagName == "s:list":
                    value = list()
                    for node in container.childNodes:
                        if node.firstChild is None:
                            value.append("")
                        else:
                            value.append(node.firstChild.nodeValue)
            else:
                value = data.firstChild.nodeValue
            p[key] = value
        return p

    @property
    def pools(self):
        if self._pool_info is None:
            self._pool_info = self._url_get('LICENSE_POOL')

        pool_data = map(self._get_pool_data, self._pool_info.getElementsByTagName('entry'))
        return pool_data

class CheckSplunk(pynagios.Plugin):
    username = pynagios.make_option("-u", type="string")
    password = pynagios.make_option("-p", type="string")
    index = pynagios.make_option("-I", type="string", default="main")
    license_pool = pynagios.make_option("-L", type="string", default="auto_generated_pool_enterprise")
    warn = pynagios.make_option("-W", type="int", default=75)
    crit = pynagios.make_option("-C", type="int", default=90)

    def __init__(self, *args, **kwargs):
        super(CheckSplunk, self).__init__(*args, **kwargs)
        splunk_kwargs = {
            'index_name': self.options.index,
            'license_pool': self.options.license_pool,
            'license_hash': self.options.license_pool, # See note in check_license_expiration
        }
        self.splunk = SplunkServer(self.options.hostname, self.options.username, self.options.password, **splunk_kwargs)

    def check(self):
        check = self.args[1]
        if hasattr(self, "check_%s" % check):
            return getattr(self, "check_%s" % check)()
        else:
            return pynagios.Response(pynagios.UNKNOWN, "Invalid check requested")

    def check_license(self):
        if self.splunk.isFree:
            return pynagios.Response(pynagios.OK, "Splunk Community Edition")

        if self.splunk.isTrial:
            return pynagios.Response(pynagios.OK, "Splunk Download Trial")

        # Request list of licenses
        licenses = self.splunk.licenses

        valid_licenses = filter(lambda l: licenses[l]['status'] == 'VALID', licenses.keys())
        valid_licenses = filter(lambda l: licenses[l]['type'] == 'enterprise', valid_licenses)

        try:
            quota = sum(map(lambda l: int(licenses[l]['quota']), valid_licenses))
        except:
            quota = 0

        if quota == 0:
            return pynagios.Response(pynagios.CRITICAL, "No valid licenses available")

        # Get the pool's current usedBytes value
        used_bytes = sum(map(lambda p: int(p['used_bytes']), self.splunk.pools))

        WARN_QUOTA = self.options.warn * quota / 100
        CRIT_QUOTA = self.options.crit * quota / 100

        USED_PERCENT = int(used_bytes * 100 / quota)

        output_string = "%d%% of license capacity is used" % USED_PERCENT
        if used_bytes > CRIT_QUOTA:
            result = pynagios.Response(pynagios.CRITICAL, output_string)
        elif used_bytes > WARN_QUOTA:
            result = pynagios.Response(pynagios.WARNING, output_string)
        else:
            result = pynagios.Response(pynagios.OK, output_string)

        result.set_perf_data("used", used_bytes, "")
        result.set_perf_data("quota", quota, "")
        return result

    def check_index(self):
        USED_PERCENT = int(self.splunk.current_db_size * 100 / self.splunk.max_db_size)

        output_string = "%d%% of MaxTotalDBSize is used" % USED_PERCENT
        if USED_PERCENT > self.options.crit:
            result = pynagios.Response(pynagios.CRITICAL, output_string)
        elif USED_PERCENT > self.options.warn:
            result = pynagios.Response(pynagios.WARNING, output_string)
        else:
            result = pynagios.Response(pynagios.OK, output_string)

        result.set_perf_data("currentDBSizeMB", self.splunk.current_db_size, "")
        result.set_perf_data("maxTotalDataSizeMB", self.splunk.max_db_size, "")
        return result

    def check_license_expiration(self):
        # For now I'm going to reuse -L but this might change in the future.
        # This means we refer to the license hash as "license_pool" internally in a few places.
        # Boo. Let's fix that later.
        expire_ts = self.splunk.license_expiration_time
        now_ts = int(time.time())

        if expire_ts <= now_ts:
            # Exit now, its expired
            return pynagios.Response(pynagios.CRITICAL, "License %s is expired" % self.options.license_pool)

        diff_secs = expire_ts - now_ts
        diff_days = int(diff_secs / 86400)

        if diff_days < self.options.crit:
            return pynagios.Response(pynagios.CRITICAL, "License %s expires in %d days" % (self.options.license_pool, diff_days))
        elif diff_days < self.options.warn:
            return pynagios.Response(pynagios.WARNING, "License %s expires in %d days" % (self.options.license_pool, diff_days))
        else:
            return pynagios.Response(pynagios.OK, "License %s expires in %d days" % (self.options.license_pool, diff_days))

if __name__ == '__main__':
    CheckSplunk().check().exit()

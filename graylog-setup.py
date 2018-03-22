#!/usr/bin/env python
# -*- coding: utf-8 -*-

############################################################################################
# graylog_setup.py:   Graylog2 logging server setup script
# Author:   VIVI | <Blog: thevivi.net> | <Twitter: @_theVIVI> | <Email: gabriel@thevivi.net> 
############################################################################################

import subprocess
import argparse
import hashlib
import sys
import re
import os

# Console colours
W = '\033[0m'     #normal
R = '\033[1;31m'  #red
T = '\033[1;93m'  #tan
LG = '\033[1;32m' #light green

# Default configurations
username = 'admin'
password = 'Str0ng_Pa55w0rd'
bind_port = '9000'

# OpenSSL config
# Change 127.0.0.1 value to match your IP address
openssl_config = '''
[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

# Details about the issuer of the certificate
[req_distinguished_name]
C = US
ST = NY
L = NY
O = Graylog
OU = Graylog
CN = logger.graylog.com

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

# IP addresses and DNS names the certificate should include
# Use IP.### for IP addresses and DNS.### for DNS names,
# with "###" being a consecutive number.
[alt_names]
IP.1 = 127.0.0.1
DNS.1 = logger.graylog.com
'''

def parse_args():

	# Arguments
	parser = argparse.ArgumentParser(description='Graylog2 logging' +
		' server setup script')

	return parser.parse_args()

def shutdown():

	# User shutdown
	print '\n' + R + '[!]' + W + ' Exiting.'
	sys.exit()

def get_requirements():

	print '\n' + T + '[*]' + W + ' Installing prerequisites...\n'

	# Add Debian Jessie backports to sources.list
	jessie_backports = '''
# Jessie backports
deb http://ftp.debian.org/debian jessie-backports main
	'''
	update_apt_sources = open('/etc/apt/sources.list', 'a')
	update_apt_sources.write(jessie_backports)
	update_apt_sources.close()

	# Update & upgrade
	subprocess.call(['apt-get', 'update'])
	subprocess.call(['apt-get', 'upgrade', '-y'])

	# Install Java
	subprocess.call(['apt-get', 'install', '-y', 'apt-transport-https', 'openjdk-8-jre-headless', \
	 'uuid-runtime', 'pwgen', 'dirmngr'])

	# Install repos

	# MongoDB
	subprocess.call(['apt-key', 'adv', '--keyserver', 'hkp://keyserver.ubuntu.com:80', \
	'--recv', '2930ADAE8CAF5059EE73BB4B58712A2291FA4AD5'])
	mongodb_repo = 'deb http://repo.mongodb.org/apt/debian jessie/mongodb-org/3.6 main'
	mongodb_apt = open('/etc/apt/sources.list.d/mongodb-org-3.6.list', 'w')
	mongodb_apt.write(mongodb_repo)
	mongodb_apt.close()

	# ElasticSearch
	proc = subprocess.Popen(['wget', '-qO', '-', \
		'https://artifacts.elastic.co/GPG-KEY-elasticsearch'], stdout=subprocess.PIPE)
	elasticsearch_key = proc.stdout.read()
	elasticsearch_gpg = open('/tmp/elasticsearch.gpg', 'w')
	elasticsearch_gpg.write(elasticsearch_key)
	elasticsearch_gpg.close()
	subprocess.call(['apt-key', 'add', '/tmp/elasticsearch.gpg'])
	elasticsearch_repo = 'deb https://artifacts.elastic.co/packages/5.x/apt stable main'
	elasticsearch_apt = open('/etc/apt/sources.list.d/elastic-5.x.list', 'w')
	elasticsearch_apt.write(elasticsearch_repo)
	elasticsearch_apt.close()

	# Graylog
	subprocess.call(['wget', '-O', '/tmp/graylog-2.4-repo.deb', \
	 'https://packages.graylog2.org/repo/packages/graylog-2.4-repository_latest.deb'])
	subprocess.call(['dpkg', '-i', '/tmp/graylog-2.4-repo.deb'])

	# Update
	subprocess.call(['apt-get', 'update'])

	# Install prerequisites
	subprocess.call(['apt-get', 'install', '-y', 'mongodb-org', 'elasticsearch'])

	# Backup ElasticSearch config
	if not os.path.isfile("/etc/elasticsearch/elasticsearch.yml.bak"):
		subprocess.call(['cp', '/etc/elasticsearch/elasticsearch.yml', \
			'/etc/elasticsearch/elasticsearch.yml.bak'])
	
	# Modify ElasticSearch config
	ec1 = open('/etc/elasticsearch/elasticsearch.yml', 'r')
	old_config = ec1.read()
	ec1.close()
	cluster_tag = re.compile(r"name for your cluster:.*?#web_endpoint_uri =", flags=re.DOTALL)
	new_config = cluster_tag.sub(lambda match: \
		match.group(0).replace('#cluster.name: my-application','cluster.name: graylog') ,old_config)
	ec2 = open('/etc/elasticsearch/elasticsearch.yml', 'w')
	ec2.write(new_config)
	ec2.close()

	print '\n' + LG + '[!]' + W + ' Prerequistes installed.'

def get_graylog():

	# Install Graylog
	print '\n' + T + '[*]' + W + ' Installing Graylog2...\n'
	subprocess.call(['apt-get', 'install', '-y', 'graylog-server'])

	print '\n' + T + '[*]' + W + ' Enabling services...\n'
	subprocess.call(['systemctl', 'daemon-reload'])
	subprocess.call(['systemctl', 'enable', 'mongod.service', 'elasticsearch.service', \
		'graylog-server.service',])
	subprocess.call(['systemctl', 'restart', 'mongod.service', 'elasticsearch.service'])

	print '\n' + LG + '[!]' + W + ' Graylog2 installed.'

def configure_graylog():
	
	# Backup Graylog config
	print '\n' + T + '[*]' + W + ' Configuring Graylog...\n'

	if not os.path.isfile("/etc/graylog/server/server.conf.bak"):
		subprocess.call(['cp', '/etc/graylog/server/server.conf', \
			'/etc/graylog/server/server.conf.bak'])

	# Generate config data

	# Admin username
	root_name = 'root_username = ' + str(username)
	# root_password_sha2
	sha256 = hashlib.sha256()
	password_hash = hashlib.sha256(password).hexdigest()
	root_hash = 'root_password_sha2 = ' + str(password_hash)
	# password_secret
	proc = subprocess.Popen(['pwgen', '-N', '1', '-s', '96'], stdout=subprocess.PIPE)
	password_secret = proc.stdout.read()
	password_secret = password_secret[:-1]
	secret_key = 'password_secret = ' + str(password_secret)
	# Bind port
	port='0.0.0.0:'+str(bind_port)

	# Modify Graylog config
	gc1 = open('/etc/graylog/server/server.conf', 'r')
	old_config = gc1.read()
	gc1.close()
	config_tag = re.compile(r"is_master = true.*?# be tore down", flags=re.DOTALL)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('password_secret =',str(secret_key)) ,old_config)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('#root_username = admin',str(root_name)) ,new_config)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('root_password_sha2 =',str(root_hash)) ,new_config)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('#web_listen_uri','web_listen_uri') ,new_config)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('127.0.0.1:9000',str(port)) ,new_config)
	gc2 = open('/etc/graylog/server/server.conf', 'w')
	gc2.write(new_config)
	gc2.close()

def configure_https():
	
	print '\n' + T + '[*]' + W + ' Configuring HTTPS...\n'

	# Create SSL directory
	subprocess.call(['mkdir', '/etc/graylog/server/ssl'])

	# OpenSSL config
	cert_config = open('/etc/graylog/server/ssl/openssl-graylog.cnf', 'w')
	cert_config.write(openssl_config)
	cert_config.close()
	
	# Create cert and private key            
	subprocess.call(['openssl', 'req', '-x509', '-days', '365', '-nodes', '-newkey', \
		'rsa:2048', '-config', '/etc/graylog/server/ssl/openssl-graylog.cnf', \
		'-keyout', '/etc/graylog/server/ssl/pkcs5-plain.pem', '-out', \
		'/etc/graylog/server/ssl/graylog.crt'])	
	subprocess.call(['openssl', 'pkcs8', '-in', '/etc/graylog/server/ssl/pkcs5-plain.pem', \
		'-topk8', '-nocrypt', '-out', '/etc/graylog/server/ssl/graylog.key'])
	subprocess.call(['chmod', '644', '/etc/graylog/server/ssl/graylog.crt'])
	subprocess.call(['chmod', '644', '/etc/graylog/server/ssl/graylog.key'])
	
	# Add cert to JVM trust-store	   
	subprocess.call(['cp', '-a', '/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/security/cacerts', \
		'/etc/graylog/server/ssl/'])     
	subprocess.call(['keytool', '-importcert', '-keystore', '/etc/graylog/server/ssl/cacerts', \
		'-storepass', 'changeit', '-alias', '-graylog-self-signed', '-file', \
		'/etc/graylog/server/ssl/graylog.crt'])

	# Modify Graylog config
	gc1 = open('/etc/graylog/server/server.conf', 'r')
	old_config = gc1.read()
	gc1.close()
	config_tag = re.compile(r"is_master = true.*?# be tore down", flags=re.DOTALL)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('#rest_enable_tls = true','rest_enable_tls = true') ,old_config)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('#rest_tls_cert_file = /path/to/graylog.crt',\
			'rest_tls_cert_file = /etc/graylog/server/ssl/graylog.crt') ,new_config)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('#rest_tls_key_file = /path/to/graylog.key',\
			'rest_tls_key_file = /etc/graylog/server/ssl/graylog.key') ,new_config)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('#web_enable_tls = true','web_enable_tls = true') ,new_config)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('#web_tls_cert_file = /path/to/graylog-web.crt',\
			'web_tls_cert_file = /etc/graylog/server/ssl/graylog.crt') ,new_config)
	new_config = config_tag.sub(lambda match: \
		match.group(0).replace('#web_tls_key_file = /path/to/graylog-web.key',\
			'web_tls_key_file = /etc/graylog/server/ssl/graylog.key') ,new_config)
	gc2 = open('/etc/graylog/server/server.conf', 'w')
	gc2.write(new_config)
	gc2.close()

	# Restart Graylog
	print '\n' + T + '[*]' + W + ' Restarting Graylog...\n'
	subprocess.call(['service', 'graylog-server', 'restart'])

# Main section
if __name__ == "__main__":

	print """                         
  _____                 _                _____      _               
 / ____|               | |              / ____|    | |              
| |  __ _ __ __ _ _   _| | ___   __ _  | (___   ___| |_ _   _ _ __  
| | |_ | '__/ _` | | | | |/ _ \ / _` |  \___ \ / _ \ __| | | | '_ \ 
| |__| | | | (_| | |_| | | (_) | (_| |  ____) |  __/ |_| |_| | |_) |
 \_____|_|  \__,_|\__, |_|\___/ \__, | |_____/ \___|\__|\__,_| .__/ 
                   __/ |         __/ |                       | |    
                  |___/         |___/                        |_|    
                                                                 
	"""

	# Parse args
	args = parse_args()

	# Root check
	if os.geteuid():
		sys.exit('[' + R + '-' + W + ']' +
			' This script must be run as root.')

	try:
		get_requirements()
		get_graylog()
		configure_graylog()
		configure_https()

		print '\n' + LG + '[!] Graylog2 succefully installed!\n' + W
		
		# Login details
		print T + 'URL:' + W + ' https://[YOUR_IP_ADDRESS]:%s' % bind_port
		print T + 'Username:' + W + ' %s' % username
		print T + 'Password:' + W + ' %s' % password

	except KeyboardInterrupt:
		shutdown()
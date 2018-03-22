# Graylog-Setup
Graylog2 logging server setup script.

### Usage:
Change the following settings at the top of the script before running it:
1. username = 'admin'
2. password = 'Str0ng_Pa55w0rd'
3. bind_port = '9000'
4. In openssl_config, change the 'IP.1 = 127.0.0.1' to match the IP address of your server i.e. IP.1 = YOUR_IP_ADDRESS

### Example:
$ sudo python graylog-setup.py

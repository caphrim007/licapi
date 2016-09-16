import sys
import requests
import time
from logger import Logger

requests.packages.urllib3.disable_warnings()

try:
    import json as json_out 
except ImportError:
    import simplejson as json_out

class License(object):
    """
    License Pool for BIGIPs
    """
    logger = Logger.create_logger(__name__)
    def __init__(self, config=None):
        self.config = config

    def license_pool(self, config):
        """
	Trust # BIGIP
    	"""
	iq = self.config['bigiq']
        ip = config['bigip']
        username = config['username']
        password = config['password']
        root_username = config['root_username']
        root_password = config['root_password']
        base_reg_key = config['baseregkey']

	self.logger.info("Licensing for BIGIP {0}".format(ip))
	uri = 'https://' + iq + '/mgmt/cm/shared/licensing/pools'
        response = requests.get(uri, auth=(username, password), verify=False)

	# dump json trust task
	json_str = response.json()

        for item in json_str['items']: 
           if item['baseRegKey'] == base_reg_key:
               member_uuid=item['uuid']

        uri = 'https://' + iq + '/mgmt/cm/shared/licensing/pools/' + member_uuid + '/members'
        lic_json = {"deviceAddress": ip,"username": username,"password": password}

        self.logger.info("BIGIQ HTTPS POST to licence worker on behalf of BIGIP {0}".format(ip))
        response = requests.post(uri, data=str(lic_json), auth=(username, password), verify=False)
        json_str = response.json()
        time.sleep(5)

        try:
            uri = json_str['selfLink'].replace('localhost', iq)
            i=0
            while True:
                response = requests.get(uri, auth=(username, password), verify=False)
                json_str = response.json()


                if json_str['state'] == 'LICENSED':
                    return True
                    break
                elif json_str['state'] == 'FAILED':
                    return False
                    break
                else:
                    time.sleep(1)
                    i+=1
                    self.logger.info("BIGIP Licence State = {0} expecting LICENSED. {1}".format(json_str['state'], i))
        except:
            return False

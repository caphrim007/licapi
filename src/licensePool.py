#!/usr/bin/env python
# -*- coding: utf-8 -*-

#@Author: Carl Dubois
#@Email: c.dubois@f5.com
#@Description: Licence an unmanaged BIGIP
#@Product: BIGIQ
#@VersionIntroduced: 5.0.0

"""
licence BIGP
"""

import sys
import argparse
from license import License
from time import strftime
from logger import Logger

def wf_license(LOGGER, lic, config, args):
    
    result = []

    #=================================
    # Add BIGIP member to license pool
    #=================================
    result = lic.license_pool(config)
    return result

if __name__ == '__main__':
    #==========================
    # Logger
    #==========================
    LOGGER = Logger.create_logger(__name__)

    #==========================
    # Help
    #==========================
    parser = argparse.ArgumentParser(description='License a unmanaged BIGIP or pool of BIGIPs.')
    parser.add_argument('--config', type=str, help='Configuration,IQ-IP address, user, pass.')

    args = parser.parse_args()

    #==========================
    # Read config file
    #==========================
    file = args.config
    config={}

    if file:
    	file = '../../config/{0}'.format(file)
	with open (file) as infile:
	    print infile
	    for line in infile:
               (key, val) = line.split(' = ')
               config[str(key)] = val.strip('\n')
    else:
	LOGGER.error("No configuration file.")
	sys.exit(1)

    #==========================
    # License
    #==========================
    License = License(config)
    result = wf_license(LOGGER, License, config, args) 
    
    if result==True:
        LOGGER.info("BIGIP Licence State = LICENSED. SUCCESS")
    else:
        LOGGER.info("BIGIP Licence State = FAILED.")

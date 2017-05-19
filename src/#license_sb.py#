#!/usr/bin/env python
# -*- coding: utf-8 -*-

#@Author: Carl Dubois
#@Email: c.dubois@f5.com
#@Description: License an unmanaged BIGIP. Utility reg keys.
#@Product: BIGIQ
#@VersionIntroduced: 5.1.0

"""
License BIGP. Utility registration keys. 
Dependencies:
1. python requests
2. python re, for regular expressions
3. python logger, used to info, debug and error logging

Usage:
./license_sb.py -h
usage: license_sb.py [-h] [-name NAME] [-type TYPE] [-iq IQ]
                     [-iq_user IQ_USER] [-iq_pass IQ_PASS] [-ip IP]
                     [-ip_user IP_USER] [-ip_pass IP_PASS] [-clp_f CLP_F]
                     [-clp_t CLP_T] [-clp_u CLP_U]

License a unmanaged BIGIP using built in registration keys.

optional arguments:
  -h, --help        Show this help message and exit
  -name NAME        Name of reg key pool. If it does not exist, create.
  -type TYPE        License Key Type used by BIGIQ. ex. regkey, clp
  -iq IQ            Network address of BIGIQ.
  -iq_user IQ_USER  Username of BIGIP
  -iq_pass IQ_PASS  Password if BIGIP
  -ip IP            Network address of BIGIP to license.
  -ip_user IP_USER  Username of BIGIP
  -ip_pass IP_PASS  Password if BIGIP
  -clp_f CLP_F      CLP feature set. ex. LTM | BETTER | BEST
  -clp_t CLP_T      CLP throughput. ex. 25M | 200M | 1G
  -clp_u CLP_U      CLP unit-of-measure. ex. hourly | daily | monthly
"""

import sys
import argparse
import requests
import re
import time
from logger import Logger

try:
    import json
except ImportError:
    import simplejson as json

# disable request package warnings
requests.packages.urllib3.disable_warnings()

def regkey(logger, args):
    """
    Function to enumerate list of reg keys.
    Find an avalible reg key.
    License the specified BIGIP device.
    """

    #debug
    #logger.debug(json.dumps(item, default=lambda o: o.__dict__, sort_keys=True, indent=4))
    ##=========================
    # Find a avalible Reg Key
    ##=========================
    logger.info("Enumerate all Reg Key pool to find: {0}".format(args.name))
    uri = 'https://' + args.iq + '/mgmt/cm/device/licensing/pool/regkey/licenses'
    response = requests.get(uri, auth=(args.iq_user, args.iq_pass), verify=False)
    offerings=[]
    i=0
    if response.status_code==200:
        ##=========================================================================================
        # If regkey name is found in list add offerings to list, else create new reg key and exit.
        ##=========================================================================================
       for item in response.json()['items']:
            if item['name'] == args.name:
                logger.info('Found Reg Key pool: {0}'.format(args.name))
                uri_rk=item['selfLink'].replace('localhost', args.iq)
                uri_rk += "/offerings"

                ## Get offering base-reg-keys
                response = requests.get(uri_rk, auth=(args.iq_user, args.iq_pass), verify=False)
                if response.status_code==200:
                    for item in response.json()['items']:
                        offerings.append(uri_rk + '/' + item['regKey'])
                else:
                    logger.error('GET base-reg-key pool offerings failed.')
                
                if len(offerings)==0:
                    logger.info("There are no license offerings avalible for reg key: {0}. Please add.".format(args.name))
                    sys.exit(1)
                # Found reg key pool.
                break
       else:
           logger.info('Could not find reg key pool. Create a new one called {0}'.format(args.name))
           ## Code to create new pool.
           key_json = {"name": args.name, "description": "New regkey offering"}
           response = requests.post(uri, data=str(key_json), auth=(args.ip_user, args.ip_pass), verify=False)
           if response.status_code==200:
               logger.info("{0} with ID: {1} created.".format (response.json()['name'], response.json()['id']))
           else:
               logger.error('POST base-reg-key pool offerings failed.')
               sys.exit(1)
    else:
        logger.error("GET failed for pool.")

    ##================================================================================================
    # Next lets find out if there are devices already licensed for these offerings discovered above.
    ##================================================================================================
    for i in range (len(offerings)):
        offerings[i] += '/members'
        response = requests.get(offerings[i], auth=(args.iq_user, args.iq_pass), verify=False)
        offering = re.search(r'(offerings)/(.*\w\d)', offerings[i])
        if response.status_code==200:
            if len(response.json()['items'])==0:
                logger.info('There are no devices for offering: {0}. POST device {1} to be licensed'.format(offering.group(2), args.ip))
                # POST data a device to this offering
                lic_json = {"deviceAddress": args.ip,"username": args.ip_user,"password": args.ip_pass}
                logger.info("BIGIQ POST a reg key license from offering {0} to BIGIP device {1}".format(offering.group(2), args.ip))
                response = requests.post(offerings[i], data=str(lic_json), auth=(args.ip_user, args.ip_pass), verify=False)
                
                logger.info('Test device {0} licensing status is LICENSED'.format(args.ip))
                # Test if device is licensed.
                if response.status_code==200:
                    while True:
                        response = requests.get(offerings[i], auth=(args.iq_user, args.iq_pass), verify=False)
                        if response.status_code==200:
                            for item in response.json()['items']:
                                if item['status'] == 'LICENSED':
                                    return True
                                else:
                                    logger.info(item['status'])
                                    time.sleep(2)
                        else:
                            logger.error('Get status failed {0}'.format(response.json()))
                            return False
                else:
                    logger.info(json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4))
    else:
        logger.info("There are no avalible offerings for RegKey: {0} to license BIGIP {1}".format(args.name, args.ip))

def clp(logger, args):
    options=[]
    ##=========================
    # Find a avalible Reg Key
    ##=========================
    logger.info("Enumerate utility license to find Reg Key")
    uri = 'https://' + args.iq + '/mgmt/cm/system/licensing/utility-licenses'
    response = requests.get(uri, auth=(args.iq_user, args.iq_pass), verify=False)
    if response.status_code==200:
        ##=========================================================================================
        # A Utility Reg Key must be present. The below will attempt to find the one specified.
        ##=========================================================================================
        for item in response.json()['items']:
            if item['name'] == args.name:
                logger.info('Found Utility Reg Key for: {0}'.format(args.name))
                uri_clp=item['selfLink'].replace('localhost', args.iq)
                uri_clp += "/offerings"
                break
            else:
                continue
        else:
            logger.info('Could not find utility reg key: {0}'.format(args.name))
            return False
    else:
        logger.error(json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4))
        return False

    ###==========================================================================================================
    # Now that we have the Reg Key, lets attempt to find the offering requested based on Feature and Throughput.
    ###==========================================================================================================
    response = requests.get(uri_clp, auth=(args.iq_user, args.iq_pass), verify=False)
    if response.status_code==200:
        for item in response.json()['items']:
            try:
                offering = re.search(r'F5-BIG-MSP-([A-Za-z]+)-([a-zA-Z0-9]+)-LIC-DEV', item['name'])
                if offering.group(1)==args.clp_f and offering.group(2)==args.clp_t:
                    break
                else:
                    continue 
            except:
                continue
        else:
            logger.error("Could not find an offering that was requested - Feature: {0} Throughput: {1}".format(args.clp_f, args.clp_t))
            return False

        uri_clp=item['selfLink'].replace('localhost', args.iq)

    ###=========================================================================================
    # Know that we have the offering requested. Lets make sure its READY for licensing.
    ###=========================================================================================
    response = requests.get(uri_clp, auth=(args.iq_user, args.iq_pass), verify=False)
    if response.status_code==200:
        if response.json()['status']=='READY':
            uri_clp += '/members'
            logger.info("POST device {0} for licensing as status is {1}".format(args.ip, response.json()['status']))
            lic_json = {"deviceAddress": args.ip,"username": args.ip_user,"password": args.ip_pass, "unitOfMeasure":args.clp_u}
            response = requests.post(uri_clp, data=str(lic_json), auth=(args.ip_user, args.ip_pass), verify=False)
                
            logger.info('Test device {0} licensing status is LICENSED'.format(args.ip))
            # Test if device is licensed.
            if response.status_code==200:
                while True:
                    response = requests.get(uri_clp, auth=(args.iq_user, args.iq_pass), verify=False)
                    if response.status_code==200:
                        for item in response.json()['items']:
                            if item['status'] == 'LICENSED':
                                return True
                            else:
                                logger.info(item['status'])
                                time.sleep(2)
                    else:
                        logger.error('Get status failed {0}'.format(response.json()))
                        return False
            else:
                logger.info(json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4))
            
        else:
            logger.error("The utility offering requested: {0} is not READY for licensing. Status is: {1}".format(response.json()['name'], response.json()['status']))
            return False
    else:
        logger.error("GET failed for utility offering.")

if __name__ == '__main__':
    #==========================
    # Logging
    #==========================
    LOGGER = Logger.create_logger(__name__)

    #==========================
    # Help
    #==========================
    parser = argparse.ArgumentParser(description='License a unmanaged BIGIP using built in registration keys.')
    parser.add_argument('-name', type=str, help='Name of reg key pool. If it does not exist, create.')
    parser.add_argument('-type', type=str, help='License Key Type used by BIGIQ. ex. regkey, clp')
    parser.add_argument('-iq', type=str, help='Network address of BIGIQ.')
    parser.add_argument('-iq_user', type=str, help='Username of BIGIP')
    parser.add_argument('-iq_pass', type=str, help='Password if BIGIP')
    parser.add_argument('-ip', type=str, help='Network address of BIGIP to license.')
    parser.add_argument('-ip_user', type=str, help='Username of BIGIP')
    parser.add_argument('-ip_pass', type=str, help='Password if BIGIP')
    parser.add_argument('-clp_f', type=str, help='CLP feature set. ex. LTM | BETTER | BEST')
    parser.add_argument('-clp_t', type=str, help='CLP throughput. ex. 25M | 200M | 1G')
    parser.add_argument('-clp_u', type=str, help='CLP unit-of-measure. ex. hourly | daily | monthly')

    #==========================
    # Parser arguments
    #==========================
    args = parser.parse_args()
    result_rk=result_clp=False
   
    if args.type=='regkey':
        #==========================
        # RegKey License Funtion
        #==========================
        result_rk = regkey(LOGGER, args) 
    elif args.type=='clp':
        #==========================
        # CLP License Funtion
        #==========================
        result_clp = clp(LOGGER, args) 
    else:
        LOGGER.error("License type {0} not implemented or does not exist.".format(args.type))

    if result_rk or result_clp == True:
        LOGGER.info("BIGIP {0} licence state = LICENSED. SUCCESS".format(args.ip))
    else:
        LOGGER.info("BIGIP {0} Licence State = FAILED.".format(args.ip))

    


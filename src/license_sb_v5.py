#!/usr/bin/env python
# -*- coding: utf-8 -*-

#@Author: Carl Dubois
#@Email: c.dubois@f5.com
#@Description: License an unmanaged BIGIP. Utility reg keys.
#@Product: BIGIQ
#@VersionIntroduced: 5.1.0

"""
Copyright 2017 by F5 Networks Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


License BIGP. Utility registration keys. 
Dependencies:
1. python requests
2. python re, for regular expressions

Usage:
./license_sb.py -h
usage: license_sb.py [-h] [-name NAME] [-type TYPE] [-iq IQ]
                     [-iq_user IQ_USER] [-iq_pass IQ_PASS] [-ip IP]
                     [-ip_user IP_USER] [-ip_pass IP_PASS] [-clp_f CLP_F]
                     [-clp_t CLP_T] [-clp_u CLP_U]

License a unmanaged BIGIP using built in registration keys.

optional arguments:
  -h, --help        Show this help message and exit
  -name NAME        Name of license pool in BIGIQ.
  -type TYPE        License Key Type used by BIGIQ. ex. regkey, clp
  -iq IQ            Network address of BIGIQ.
  -iq_user IQ_USER  Administrator username of BIGIQ.
  -iq_pass IQ_PASS  Administrator password if BIGIQ.
  -ip IP            Network address of BIGIP to license.
  -ip_user IP_USER  Administrator username of BIGIP
  -ip_pass IP_PASS  Adminsitrator password if BIGIP
  -clp_f CLP_F      CLP feature set. ex. LTM | BETTER | BEST
  -clp_t CLP_T      CLP throughput. ex. 25M | 200M | 1G
  -clp_u CLP_U      CLP unit-of-measure. ex. hourly | daily | monthly
"""

import sys
import argparse
import requests
import re
import time
import os

try:
    import json
except ImportError:
    import simplejson as json

# disable request package warnings
requests.packages.urllib3.disable_warnings()

def regkey(args):
    """
    Function to enumerate list of reg keys.
    Find an avalible reg key.
    License the specified BIGIP device.
    """

    if args.op == 'grant':
        ##=========================
        # Find a avalible Reg Key
        ##=========================
        print "Enumerate all Reg Key pool to find: {0}".format(args.name)
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
                    print 'Found Reg Key pool: {0}'.format(args.name)
                    uri_rk=item['selfLink'].replace('localhost', args.iq)
                    uri_rk += "/offerings"

                    ## Get offering base-reg-keys
                    response = requests.get(uri_rk, auth=(args.iq_user, args.iq_pass), verify=False)
                    if response.status_code==200:
                        for item in response.json()['items']:
                            offerings.append(uri_rk + '/' + item['regKey'])
                    else:
                        print 'GET base-reg-key pool offerings failed.'
                
                    if len(offerings)==0:
                        print "There are no license offerings avalible for reg key: {0}. Please add.".format(args.name)
                        sys.exit(1)
                    # Found reg key pool.
                    break
            else:
                print 'ERROR: Could not find avalible reg key pool {0}.'.format(args.name)
                return False
        else:
            print "ERROR: GET failed for pool."

        ##================================================================================================
        # Next lets find out if there are devices already licensed for these offerings discovered above.
        ##================================================================================================
        for i in range (len(offerings)):
            offerings[i] += '/members'
            response = requests.get(offerings[i], auth=(args.iq_user, args.iq_pass), verify=False)
            offering = re.search(r'(offerings)/(.*)./', offerings[i])
        
            # Test to find license key
            if offering is None:
                print "ERROR: Could not find license key offering."
                return False

            if response.status_code==200:
                if len(response.json()['items'])==0:
                    print 'INFO: There are no devices for offering: {0}. POST device {1} to be licensed'.format(offering.group(2), args.ip)
                    # POST data a device to this offering
                    lic_json = {"deviceAddress": args.ip,"username": args.ip_user,"password": args.ip_pass}
                    print "INFO: BIGIQ POST a reg key license from offering {0} to BIGIP device {1}".format(offering.group(2), args.ip)
                    response = requests.post(offerings[i], data=str(lic_json), auth=(args.ip_user, args.ip_pass), verify=False)
                
                    print 'INFO: Test device {0} licensing status is LICENSED'.format(args.ip)
                    # Test if device is licensed.
                    if response.status_code==200:
                        while True:
                            response = requests.get(offerings[i], auth=(args.iq_user, args.iq_pass), verify=False)
                            if response.status_code==200:
                                for item in response.json()['items']:
                                    if item['status'] == 'LICENSED':
                                        return True
                                    elif item['status'] == 'INSTALLATION_FAILED':
                                        print 'ERROR: INSTALLATION_FAILED'
                                        return False
                                    else:
                                        print item['status']
                                        time.sleep(2)
                            else:
                                print 'ERROR: Get status failed {0}'.format(response.json())
                                return False
                    else:
                        print json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4)
        
            else:
                print "ERROR: Reponse from GET offerings failed. Check if BIG-IQ auth is enabled. BIG-IQ shell set-basic-auth on"
                print json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4)
                return False
        else:
            print "INFO: There are no avalible offerings for RegKey: {0} to license BIGIP {1}".format(args.name, args.ip)
    else:
        print 'INFO: REVOKE REGKEY device license for IP: {0}'.format(args.ip)
        ##=========================
        # REVOKE DEVCE LICENSE
        ##=========================
        print "Enumerate all Reg Key pool to find: {0}".format(args.name)
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
                    print 'Found Reg Key pool: {0}'.format(args.name)
                    uri_rk=item['selfLink'].replace('localhost', args.iq)
                    uri_rk += "/offerings"
                    ## Get offering base-reg-keys
                    response = requests.get(uri_rk, auth=(args.iq_user, args.iq_pass), verify=False)
                    if response.status_code==200:
                        for item in response.json()['items']:
                            offerings.append(uri_rk + '/' + item['regKey'])
                    else:
                        print 'GET base-reg-key pool offerings failed.'
                
                    if len(offerings)==0:
                        print "There are no license offerings avalible for reg key: {0}. Please add.".format(args.name)
                        sys.exit(1)
                    # Found reg key pool.
                    break
            else:
                print 'ERROR: Could not find avalible reg key pool {0}.'.format(args.name)
                return False
        else:
            print "ERROR: GET failed for pool."

        for member in offerings:
            member+="/members"
            ## Get members for each offering
            response = requests.get(member, auth=(args.iq_user, args.iq_pass), verify=False)
            if response.status_code==200:
                for item in response.json()['items']:
                    if item['deviceAddress'] == args.ip:
                        member+= "/{0}".format(item['id'])
                        ## Delete members for offering
                        del_json = {"username":args.ip_user,"password":args.ip_pass,"id":str(item['id'])}
                        print "INFO: BIGIQ REVOKE a reg key license for BIGIP device {0}".format(args.ip)
                        response = requests.delete(member, data=str(del_json), auth=(args.ip_user, args.ip_pass), verify=False)                   
                        if response.status_code==200:
                            print "INFO: Successfully revoked BIGIP device IP:{0}".format(args.ip)
                            return True
                        else:
                            print "ERROR: response message."
                            print json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4)
                            return False
                    else:
                        print "ERROR: Unable to find a device with IP: {0}".format(args.ip)

def clp(args):
    options=[]
    if args.op == 'grant':
        ##=========================
        # Find a avalible Reg Key
        ##=========================
        print "INFO: Enumerate utility license to find license key"
        uri = 'https://' + args.iq + '/mgmt/cm/system/licensing/utility-licenses'
        response = requests.get(uri, auth=(args.iq_user, args.iq_pass), verify=False)
        if response.status_code==200:
            ##=========================================================================================
            # A Utility Reg Key must be present. The below will attempt to find the one specified.
            ##=========================================================================================
            for item in response.json()['items']:
                if item['name'] == args.name:
                    print 'INFO: Found utility license key for: {0}'.format(args.name)
                    uri_clp=item['selfLink'].replace('localhost', args.iq)
                    uri_clp += "/offerings"
                    break
                else:
                    continue
            else:
                print 'ERROR: Could not find utility license key: {0}'.format(args.name)
                return False
        else:
            print json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4)
            return False

        ###==========================================================================================================
        # Now that we have the Reg Key, lets attempt to find the offering requested based on Feature and Throughput.
        ###==========================================================================================================
        response = requests.get(uri_clp, auth=(args.iq_user, args.iq_pass), verify=False)
        if response.status_code==200:
            for item in response.json()['items']:
                try:
                    offering = re.search(r'F5-BIG-MSP-([A-Za-z]+)-([a-zA-Z0-9]+)', item['name'])
                    if offering.group(1)==args.clp_f and offering.group(2)==args.clp_t:
                        break
                    else:
                        continue 
                except:
                    continue
            else:
                print "ERROR: Could not find an offering that was requested - Feature: {0} Throughput: {1}".format(args.clp_f, args.clp_t)
                return False

            uri_clp=item['selfLink'].replace('localhost', args.iq)

        ###=========================================================================================
        # Know that we have the offering requested. Lets make sure its READY for licensing.
        ###=========================================================================================
        response = requests.get(uri_clp, auth=(args.iq_user, args.iq_pass), verify=False)
        if response.status_code==200:
            if response.json()['status']=='READY':
                uri_clp += '/members'
                print "INFO: POST device {0} for licensing as status is {1}".format(args.ip, response.json()['status'])
                lic_json = {"deviceAddress": args.ip,"username": args.ip_user,"password": args.ip_pass, "unitOfMeasure":args.clp_u}
                response = requests.post(uri_clp, data=str(lic_json), auth=(args.ip_user, args.ip_pass), verify=False)
                
                print 'INFO: Test device {0} licensing status is LICENSED'.format(args.ip)
                # Test if device is licensed.
                if response.status_code==200:
                    while True:
                        response = requests.get(uri_clp, auth=(args.iq_user, args.iq_pass), verify=False)
                        if response.status_code==200:
                            for item in response.json()['items']:
                                if item['status'] == 'LICENSED':
                                    return True
                                elif item['status'] == 'INSTALLATION_FAILED':
                                    print 'ERROR: INSTALLATION_FAILED'
                                    return False
                                else:
                                    print item['status']
                                    time.sleep(2)
                        else:
                            print 'ERROR: Get status failed {0}'.format(response.json())
                            return False
                    else:
                        print json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4)
            
            else:
                print "ERROR: The utility offering requested: {0} is not READY for licensing. Status is: {1}".format(response.json()['name'], response.json()['status'])
                return False
        else:
            print "ERROR: GET failed for utility offering."
    else:
        print 'INFO: REVOKE CLP device license for IP: {0}'.format(args.ip)
        ##=========================
        # Find a avalible Reg Key
        ##=========================
        print "INFO: Enumerate utility license to find license key"
        uri = 'https://' + args.iq + '/mgmt/cm/system/licensing/utility-licenses'
        response = requests.get(uri, auth=(args.iq_user, args.iq_pass), verify=False)
        if response.status_code==200:
            ##=========================================================================================
            # A Utility Reg Key must be present. The below will attempt to find the one specified.
            ##=========================================================================================
            for item in response.json()['items']:
                if item['name'] == args.name:
                    print 'INFO: Found utility license key for: {0}'.format(args.name)
                    uri_clp=item['selfLink'].replace('localhost', args.iq)
                    uri_clp += "/offerings"
                    break
                else:
                    continue
            else:
                print 'ERROR: Could not find utility license key: {0}'.format(args.name)
                return False
        else:
            print json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4)
            return False

        ###==========================================================================================================
        # Now that we have the Reg Key, lets attempt to find the offering requested based on Feature and Throughput.
        ###==========================================================================================================
        response = requests.get(uri_clp, auth=(args.iq_user, args.iq_pass), verify=False)
        if response.status_code==200:
            for item in response.json()['items']:
                try:
                    offering = re.search(r'F5-BIG-MSP-([A-Za-z]+)-([a-zA-Z0-9]+)', item['name'])
                    if offering.group(1)==args.clp_f and offering.group(2)==args.clp_t:
                        break
                    else:
                        continue 
                except:
                    continue
            else:
                print "ERROR: Could not find an offering that was requested - Feature: {0} Throughput: {1}".format(args.clp_f, args.clp_t)
                return False

        uri_clp=item['selfLink'].replace('localhost', args.iq)
        uri_clp += "/members"
        response = requests.get(uri_clp, auth=(args.iq_user, args.iq_pass), verify=False)
        if response.status_code==200:
                for item in response.json()['items']:
                    if item['deviceAddress'] == args.ip:
                        print str (item['id'])
                        uri_clp+="/{0}".format(item['id'])

                       ## Delete members for offering
                        del_json = {"username":args.ip_user,"password":args.ip_pass,"id":str(item['id'])}
                        print "INFO: BIGIQ REVOKE a clp reg key license for BIGIP device"
                        response = requests.delete(uri_clp, data=str(del_json), auth=(args.ip_user, args.ip_pass), verify=False)                   
                        
                        if response.status_code==200:
                            print "INFO: Successfully revoked BIGIP device IP:{0}".format(args.ip)
                            return True
                        else:
                            print "ERROR: response message."
                            print json.dumps(response.json()['message'], default=lambda o: o.__dict__, sort_keys=True, indent=4)
                            return False
                    else:
                        print "ERROR: Unable to find a device with IP: {0}".format(args.ip)
                        return False

if __name__ == '__main__':
    #==========================
    # Help
    #==========================
    parser = argparse.ArgumentParser(description='License a unmanaged BIGIP using built in registration keys.')
    parser.add_argument('-op', type=str, help='To grant or revoke a license. ex. grant, revoke')
    parser.add_argument('-name', type=str, help='Name of license pool in BIGIQ.')
    parser.add_argument('-type', type=str, help='License Key Type used by BIGIQ. ex. regkey, clp')
    parser.add_argument('-iq', type=str, help='Network address of BIG-IQ.')
    parser.add_argument('-iq_user', type=str, help='Administrator username of BIGIP')
    parser.add_argument('-iq_pass', type=str, help='Administrator password if BIGIP')
    parser.add_argument('-ip', type=str, help='Network address of BIG-IP to license.')
    parser.add_argument('-ip_user', type=str, help='Administrator username of BIGIP')
    parser.add_argument('-ip_pass', type=str, help='Administrator password if BIGIP')
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
        # check clp args
        #==========================
        if (args.clp_u != None or args.clp_t != None or args.clp_f != None):
            print "INFO: Using regkey license pool - IGNORING clp_u, clp_t, clp_f arguments."

        #==========================
        # RegKey License Funtion
        #==========================
        result_rk = regkey(args) 
    elif args.type=='clp':
        #==========================
        # CLP License Funtion
        #==========================
        result_clp = clp(args) 
    else:
        os.system("python license_sb_v4.py -h")

    if result_rk or result_clp == True:
        print "INFO: BIG-IP {0} license state = LICENSED. SUCCESS".format(args.ip)
    else:
        print "ERROR: BIG-IP {0} license state = ERROR.".format(args.ip)

    


#!/usr/bin/env python3
__author__ = "Tim Taylor"
__version__ = "Dev"
__credit__ = "Florian Roth"

"""

Inspired by Florian Roth's munin script

"""
import json
import os
import re
import requests
import sys
import time

from  argparse import ArgumentParser
from configparser import ConfigParser

class VirusShare:
    def __init__(self, apikey, lookup_type):
        self.apikey = apikey
        self.lookup_type = lookup_type

    def error_code(self, code):
        
        """

        https://virusshare.com/apiv2_reference

        204 - You are making more requests than are allowed or have exceeded your quota.
        400 - Your request was incorrect. This can be caused by missing parameters or incorrect values.
        403 - You don't have privileges to make this request. You may be making a request without providing your API key or your key may not be authorized to make the request.
        404 - The file you have requested could not be found. This is typically returned for file download requests where the file is not in the database.
        500 - This error is probably not the result of your request but rather indicates an issue with how the server handled your request.
        503 - The system is not available to process your request at this time. Please try again later.

        """
        
        response = dict()

        if code == 204:
            response = {code: 'Request rate limit exceeded'}

        elif code == 400:
            response = {code: 'Bad request'}
        
        elif code == 403:
            response = {code: 'Forbidden'}
        
        elif code == 404:
            response = {code, 'Not found'}

        elif code == 500:
            response = {code: 'Internal server error:'}
        
        elif code == 503: 
            response = {code: 'Service unavailable'}
        
        else:
            response = {code: 'Unknown Code: {} '.format(code)}

        return response


    def get_request(self, type, hash):

        json_data = ''
        hash_match = ''
        hash_len = len(hash)

        if hash_len == 32:
            hash_pattern = re.compile('^[a-fA-F0-9]{32}$')

        elif hash_len == 40:
            hash_pattern = re.compile('^[a-fA-F0-9]{40}$') 

        elif hash_len == 64:
            hash_pattern = re.compile('^[a-fA-F0-9]{64}$')

        else:
            hash_pattern = False
            json_data = False

        if hash_pattern:
            hash_match = hash_pattern.match(hash)

            URL = r'https://virusshare.com/apiv2/{}?apikey={}&hash={}'.format(self.lookup_type, self.apikey, hash)

            results =  requests.get(url = URL)

            if results.status_code != 200:
                check_status_code = self.error_code(results.status_code)

            json_data = results.json()
            json_data.update({"hash_used": hash})
        
        return json_data
 


    def throttle(self, start_time):
        throttle_time = 16
        remaining_time = max(0, throttle_time - int(time.time() - start_time))
        time.sleep(remaining_time)


    def bulk_search(self, hashes):
        results = list()
        for hash in hashes:
            start_time = time.time()
            lookup = self.get_request('file', hash)
            if lookup:
                results.append(lookup)

            self.throttle(start_time)

        
        return results


    def get_hashes_from_file(self, file):
        hashes = list()
        with open(file, 'r') as f:
            for line in f:
                hashes.append(line.rstrip())

        return hashes


    def write_output(self, data):
        for line in data:
            print(line['hash_used'])
            print(line)
            print("\n")
        

def main():
    parser = ArgumentParser(prog='VirusShare Lookups',
                            description='Bulk lookups against the VirusShare website using a personal api key',
                            usage='%(prog)s [options]',
                            epilog='Version: {}'.format(__version__))
    parser.add_argument('-f', help='Path to file containing the hashes (Required')
    parser.add_argument('-t', help='Lookup Type, Chose from file or quick quick, Default is "Quick" (Optional', 
                        choices=['quick', 'file'], default="quick")
    parser.add_argument('-v', help='Show version and exit')
    args = parser.parse_args()

    if args.v:
        print('Version: {}'.format(__version__))
        sys.exit(0)

    lookup_type = args.t
    
    script_start_time = time.time()

    api_key_file = os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]), 'apikey.txt'))

    apikey = ''
    if os.path.isfile(api_key_file):

        config = ConfigParser()
        config.read([api_key_file])
        config.apikey_config = dict(config.items("APIKEYS"))
        apikey = config.apikey_config['vs']

    else:
        print('ERROR: No {} was not found, exiting'.format(api_key_file))
        sys.exit(-1)

    hash_file = args.f

    if hash_file:
        if os.path.isfile:
            hashlookup = VirusShare(apikey, lookup_type)
            data = hashlookup.get_hashes_from_file(hash_file)
            results = hashlookup.bulk_search(data)
            hashlookup.write_output(results)

        else:
            print('ERROR: {} was not a valid file')
            sys.exit(-1)
    else:
        print('ERROR: -f is required')


if __name__ == "__main__":

    if sys.version_info[0] == 3:
        main()

    else:
        print('Python3 is required')
        print('Detected Python {}.{}.{}'.format(sys_version_info[0],sys_version_info[1],sys_version_info[2] ))

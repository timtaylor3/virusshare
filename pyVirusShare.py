#!/usr/bin/env python
__author__ = "Tim Taylor"
__version__ = "Dev"

import argparse
import re
import json

from urllib import request, parse, error, 

class VirusShare:
    def __init__(apikey):
        self.apikey = apikey

    def error_code(self, e):
        
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
        # Change response assigment to dict.

        if e.code == 204:
            response = 'Request rate limit exceeded. Error: {} {}'.format(e.code, e.reason)
        
        else if e.code == 400:
            response = 'Bad request. Error: {} {}'.format(e.code, e.reason)
        
        else if e.code == 403:
            response = 'Forbidden. Error: {} {}'.format(e.code, e.reason)
        
        else if e.code == 404:
            response = 'Not found. Error: {} {}'.format(e.code, e.reason)

        else if e.code == 500:
            response = 'Internal server error. Error: {} {}'.format(e.code, e.reason)
        
        else if e.code == 503:   
            response = 'Service unavailable. Error: {} {}'.format(e.code, e.reason)
        
        else:
            response = 'Unknown. Error: {} {} occured'.format(e.code, e.reason)

        return response

    def report(self, hash):
        
        response = ''

        try:
            data = urllib.parse.urlencode(parameters)
            data = data.encode('ascii')
            req = urllib.request.Request(url, data)
            response = urllib.request.urlopen(req)

        except urllib.error.HTTPError as e:
            response = self.error_code(e)

        json = response.read()  

        if json == '':
            raise TypeError('Too many requests')

        return response

    def bulk_search(self, file):
        pass

    def get_sha1s_from_file(self, file):
        SHA1_PATTERN = re.compile(r'[a-f\d]{40}')
        f = open(file, 'r')
        data = f.read()
        file_sha1s = re.findall(MD5_PATTERN, data)

        return file_sha1s


    def get_md5_from_file(self, file):
        MD5_PATTERN = re.compile(r'[a-f\d]{32}')
        f = open(file, 'r')
        data = f.read()
        file_md5s = re.findall(MD5_PATTERN, data)

        return file_md5s

    def j

"""
try:
        json = response.read()   
        if json == '':
            raise TypeError('Too many requests')
        dict = simplejson.loads(json)
        body += str(md5_sum) + ' found in VirusTotal Database : '
        response_code = dict['response_code']
        if response_code == 1:
            body += 'Yes\n'
            body += '  Detection Ratio : ' + str(dict['positives']) + '/' + str(dict['total']) + '\n'
            body += '  Scan Date       : ' + str(dict['scan_date'] + '\n')
            body += '  Scan URL        : ' + str(dict['permalink'] + '\n')
            if 'Symantec' in dict['scans']:
                dict = dict['scans']['Symantec']
                body += '  Symantec :\n'
                if 'detected' in dict:
                    body += '    Detection : ' + str(dict['result']) + '\n'
                    body += '    Version   : ' + str(dict['version']) + '\n'
                    body += '    Update    : ' + str(dict['update']) + '\n'
                else:
                    body += '    Detection : None\n'
            else:
                body += '  Symantec        : N/A\n'
        else:
            body += 'No\n'

    except:
        body += 'Sample MD5 could not be looked up due to an error.\n'
    print (body)
    return


"""

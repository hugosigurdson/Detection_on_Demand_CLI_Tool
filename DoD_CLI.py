#!/usr/bin/env python3
# DoD CLI Util - Show Case of how to access the FireEye Detection on Demand API Endpoints
# hugo.sigurdson@fireeye.com
# /*Copyright (C) 2020 FireEye, Inc. All Rights Reserved.*/
#
# Import required modules
import requests
import json
import hashlib
import argparse
import mime
import os
import sys
import textwrap
from pathlib import Path
from pprint import pprint
from argparse import RawTextHelpFormatter


# Build the command line interpreter, with support for RawText Formatting
parser = argparse.ArgumentParser(prog='DoD_CLI.py',
                                 formatter_class=RawTextHelpFormatter,
                                 epilog=textwrap.dedent('''\
                                 DoD CLI Util - Show Case of how to access the FireEye Detection on Demand API Endpoints
                                 hugo.sigurdson@fireeye.com
                                 Copyright (C) 2020 FireEye, Inc. All Rights Reserved.'''))
# Adds the --file argument
parser.add_argument("-F", "--file",
                    help="File(s) that you want to submit to Detection on Demand.\n"
                         "Maximum File Size is 32 MegaBytes\n"
                         "Usage Single File: --file evil.exe\n"
                         "Usage Multiple Files: -F evil.exe -f nasty.doc -f friendly.xls",
                    type=str, action='append', dest='files', metavar="<filename>")
# Adds the --hash argument
parser.add_argument("-H", "--hash",
                    help="MD5 Hash(es) that you want to submit to Detection on Demand.\n"
                         "Usage Single Hash Value: --hash 8b820...\n"
                         "Usage Multiple Hash Values: -H 8a820... -H 8b820... -H 8c820...",
                    type=str, action='append', dest='hashes', metavar="<md5 hash>")
# Adds the --md5 argument
parser.add_argument("-M", "--md5",
                    help="Create a MD5 of a file and submit to Detection on Demand\n"
                         "Usage: -M <filename>\n"
                         "Usage: --md5 <filename>",
                    type=str, dest='md5', metavar="<filename>")
# Adds the --report argument
parser.add_argument("-R", "--report",
                    help="Simplified Report(s) you want to fetch from Detection on Demand.\n"
                         "Usage Single Report ID: --report 992694b3-...\n"
                         "Usage Multiple Report IDs: -R 992694b3-... -R 992694c3-... -R 992694d3-...",
                    type=str, action='append', dest='reports', metavar="<report ID>")
# Adds the --report-extended argument
parser.add_argument("-RE", "--report-extended",
                    help="Extended Report(s) you want to fetch from Detection on Demand.\n"
                         "Usage Single Report ID: --report 992694b3-...\n"
                         "Usage Multiple Report IDs: -R 992694b3-... -R 992694c3-... -R 992694d3-...",
                    type=str, action='append', dest='reports_extended', metavar="<report id>")
# Adds the --report-list argument
parser.add_argument("-RL", "--report-list",
                    help="Lists previously submitted filenames, report IDs etc",
                    action='store_true', dest='report_list')
# Adds the --save argument
parser.add_argument("-S", "--save",
                    help="Save Option for Extended Reports\n"
                         "Saves to folder \'Extended_Reports\' in a JSON formatted file",
                    action='store_true')

args = parser.parse_args()


# Function to read the API key from the file api.key
def api_key_func():
    try:
        api_key_file = open("api.key", "r")
        api_key = api_key_file.read()
        api_key_file.close()
        return api_key
    except:
        print("No API-Key File Found, please save the API Key to a file called \"api.key\"")
        sys.exit(0)


# Set up script variables
#
# Setup default request headers
dod_request_header = {
    'accept': 'application/json',
    'feye-auth-key': api_key_func()
}


# Setup the default value for API endpoints
base_url = "https://feapi.marketplace.apps.fireeye.com"
files_api_endpoint = "/files"
hash_api_endpoint = "/hashes/"
report_api_endpoint = "/reports/"


# Function to fetch Report(s)
def func_fetch_reports(report_ids):
    for report_id in report_ids:
        fetch_report_url = base_url + report_api_endpoint + str(report_id)
        try:
            fetch_report_response = requests.get(fetch_report_url, headers=dod_request_header)
            print(fetch_report_response.status_code)
        except:
            print(fetch_report_response.status_code)
        if fetch_report_response.status_code == 200:
            pprint(fetch_report_response.json())
        else:
            print("Print Failed to fetch report")


# Function to fetch and print/save extended reports
def func_fetch_extender_reports(report_ids, save=None):
    parameters = {'extended': True}
    for report_id in report_ids:
        fetch_report_url = base_url + report_api_endpoint + str(report_id)
        try:
            fetch_report_response = requests.get(fetch_report_url, headers=dod_request_header, params=parameters)
        except:
            print(fetch_report_response.status_code)
        if fetch_report_response.status_code == 200:
            if save:
                if not os.path.exists('Extended_Reports'):
                    os.makedirs('Extended_Reports')
                else:
                    pass
                report_filename = str(report_id) + ".json"
                with open(os.path.join('Extended_Reports/', report_filename), 'w') as report_output_file:
                    json.dump(fetch_report_response.json(), report_output_file)
                print("Report saved to: " + str(os.path.join('Extended_Reports/', report_filename)))
            else:
                pprint(fetch_report_response.json())
        else:
            print("Print Failed to fetch report")


# Function to file(s) to the API for analysis
def func_post_file(files_to_open):
    post_file_url = base_url + files_api_endpoint
    for file in files_to_open:
        file_size = Path(file).stat().st_size
        file_size_mb = file_size / 1024 / 1024
        if file_size > 33554432:
            print("File is too big, maximum size is 32 MegaBytes\nFile size is: " + str(int(file_size_mb)))
        else:
            try:
                mime_type = mime.Types.of(file)[0]
                files = {'file': (file, open(file, 'rb'), mime_type.simplified)}
                post_file_response = requests.post(post_file_url, headers=dod_request_header, files=files)
            except:
                print("Status Code: " + str(post_file_response.status_code))
                print(post_file_response.reason)
            if post_file_response.status_code == 202:
                print("\nSubmitted file:\t" + str(file))
                print("Status:\t\t" + str(post_file_response.json()['status']))
                print("Report ID:\t" + str(post_file_response.json()['report_id']))
                print("MD5 Hash:\t" + str(post_file_response.json()['md5']))

                if not os.path.exists('saved_reports.json'):
                    report_list = []
                    report_dict = post_file_response.json()
                    report_dict['filename'] = file
                    report_dict['mime'] = mime_type.simplified
                    report_list.append(report_dict)
                    with open('saved_reports.json', 'w') as outfile:
                        json.dump(report_list, outfile)
                    outfile.close()
                else:
                    report_dict = post_file_response.json()
                    report_dict['filename'] = file
                    report_dict['mime'] = mime_type.simplified
                    with open('saved_reports.json') as infile:
                        data = json.load(infile)
                    infile.close()
                    data.append(report_dict)
                    with open('saved_reports.json', 'w') as outfile:
                        json.dump(data, outfile)
                    outfile.close()


# Function to submit hash(s) to API
def func_fetch_hash(hashes):
    for hash_md5 in hashes:
        check_hash_url = base_url + hash_api_endpoint + str(hash_md5)
        print("\nChecking MD5 Hash:\t" + str(hash_md5))
        try:
            hash_response = requests.get(check_hash_url, headers=dod_request_header)
        except:
            print(hash_response.status_code)
        print("AV Lookup:\t\t" + str(hash_response.json()['engine_results']['av_lookup']['verdict']))
        print("AVS Lookup:\t\t" + str(hash_response.json()['engine_results']['avs_lookup']['verdict']))
        print("Cache Lookup:\t\t" + str(hash_response.json()['engine_results']['cache_lookup']['verdict']))
        print("DTI Lookup:\t\t" + str(hash_response.json()['engine_results']['dti_lookup']['verdict']))
        print("Malicious:\t\t" + str(hash_response.json()['is_malicious']))


# Function to generate a hash from a file and then submit to API
def func_hash_file(filename):
    hash_list = []
    hash_md5 = hashlib.md5()
    with open(filename, 'rb') as input_file:
        print("Generating MD5 Hash")
        for chunk in iter(lambda: input_file.read(4096), b""):
            hash_md5.update(chunk)
            print("Generating MD5 Hash")
    hash_list.append(str(hash_md5.hexdigest()))
    print("\n")
    func_fetch_hash(hash_list)


# Function to save reports to file
def func_print_saved_reports():
    with open('saved_reports.json', 'r') as load_file:
        data = json.load(load_file)
        print("Filename,Report ID,Mime Type,Status, MD5")
        for item in data:
            print(str(item['filename']) + "," +
                  str(item['report_id']) + "," +
                  str(item['mime']) + "," +
                  str(item['status'] + ",") +
                  str(item['md5']))


# Check which arguments have been issued to script
if args.hashes:
    func_fetch_hash(args.hashes)
elif args.files:
    func_post_file(args.files)
elif args.reports:
    func_fetch_reports(args.reports)
elif args.save:
    func_fetch_extender_reports(args.reports_extended, save=True)
elif args.reports_extended:
    func_fetch_extender_reports(args.reports_extended)
elif args.md5:
    func_hash_file(args.md5)
elif args.report_list:
    func_print_saved_reports()
else:
    print("No arguments given, please use -h for help")


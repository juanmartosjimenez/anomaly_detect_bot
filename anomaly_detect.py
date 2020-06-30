import sys
import os
import gc
import sched,time
import requests
import paramiko
import math
import json
import datetime
import csv
import timeit
import subprocess
import argparse
from dateutil.relativedelta import relativedelta, MO
from termcolor import colored
import matplotlib.pyplot as plt
from matplotlib.dates import DateFormatter, DayLocator
import pandas as pd
import urllib.parse
import numpy as np
import seaborn as sns
from pytimeparse.timeparse import timeparse
from telegram_api import sendTelegramMessage,receiveMessage

#defining global variables
# number of loops before data if gathered again
loops_thresh = 20
#initializes default threshold values if there is no file with threshold values
default_thresh_dict = {'4xx': {'ip':50,'request':5}, '5xx':{'ip':20,'request':5, 'site': 10}, 'below_4xx' :{'ip':200,'request':200}}
#initializes local ips to be ignore when lookign for below 400 response anomaly
with open('database/local_ips') as f:
    local_ips = [line.strip() for line in f.readlines()]
    local_ips = ('!clientip.raw: (' + ' OR '.join(local_ips) + ')' if len(local_ips)>0 else False)

# Get objects used to define and format get request parameters
class Get():
    def __init__(self, command):
        silent = False
        if command == 0:
            self.command = 0
            self.name = 'command0'
            self.reuse_data = False
            self.query = 'site.raw: *sample_site.net AND ((response: [400 TO 499] AND !tags: static) OR (response: >499) OR (response: 200 AND !request: api))'
            self.interval = '5m'
        else:
            self.command = command
            self.name = 'command' + str(command)
            self.query = ""
            self.interval = None
        self.end = '10m'
        self.start = '0m'

    # formats start, end and interval into integer seconds of the time given
    @property
    def start(self):
        return self._start
    @start.setter
    def start(self, start):
        if type(start) is str:
            self._start = timeparse(start)
        elif type(start) is int:
            self._start = start

    @property
    def end(self):
        return self._end
    @end.setter
    def end(self, end):
        if type(end) is str:
            self._end= timeparse(end)
        elif type(end) is int:
            self._end = end

    # a change in interval will result in a change in the end date
    @property
    def interval(self):
        return self._interval
    @interval.setter
    def interval(self, date):
        if self.command == 0:
            if type(date) is str:
                self._interval= timeparse(date)
                if not self._interval:
                    raise TypeError('Timeparse expected a string received an integer in the form of a string instead')
                self.end = self._interval*2
            elif type(date) is int:
                self._interval= date
                self.end = self._interval*2

        else:
            if type(date) is str:
                self._interval = timeparse(date)
            elif type(date) is int:
                self._interval = date
            else:
                self._interval = None

    # formats name of file to be saved that stores data
    @property
    def name(self):
        return self._name
    @name.setter
    def name(self, name):
        self._name = (name if '.csv' in name else name + '.csv')
        self._name = (self._name if 'database/' in self._name else 'database/'+ self._name)

    # when print function is called the following information of the object will be printed
    def __str__(self):
        return 'Start: ' + str(self.start) + 's End: ' + str(self.end) + 's Interval: ' + str(self.interval) + 's Command: ' + str(self.command) +' Query: '+ str(self.query)[0:50] + ' ...'

    # get request and referer, command 6
    def getReferer(self, full_json):
        try:
            aggregations = full_json['aggregations']
        except KeyError as e:
            print(json.dumps(full_json, indent = 4))
            print('Key error in getServerInfo function')
            sys.exit()
        message6 = ''
        num_aggregations = list(aggregations.keys())[0]
        log_info = []
        for request in aggregations[num_aggregations]['buckets']:
            request_type = request['key']
            request_count = request['doc_count']
            for referer in request[list(request.keys())[-1]]['buckets']:
                referer_type = referer['key']
                referer_count = referer['doc_count']
                split_referer = referer_type.replace('https://','').split('/')
                log_info.append([request_type,request_count,referer_type,referer_count])
                if len(split_referer) > 1:
                    if '/' +'/'.join(split_referer[1:]) == request_type:
                        continue
                    else:
                        message6 = ' |max_referer: ' + referer_type

        if os.path.exists('database/command6.csv'):
            with open('database/command6.csv', 'a') as f:
                writer = csv.writer(f)
                writer.writerows(log_info)
        else:
            with open('database/command6.csv', 'a') as f:
                log_info.insert(0,['request','request_count','referer','referer_count'])
                writer = csv.writer(f)
                writer.writerows(log_info)

        self.message6 = message6



    # get unique count and count from query, command 5
    def getUniqueIp(self, full_json):
        try:
            aggregations = full_json['aggregations']
        except KeyError as e:
            print(json.dumps(full_json, indent = 4))
            print('Key error in getServerInfo function')
            sys.exit()
        dir5 = {}
        log_info = []
        for site in aggregations['4']['buckets']:
            site_name = site['key']
            request_count = site['doc_count']
            request_unique_count = site['3']['value']
            log_info.append([site_name, request_count, request_unique_count])
            dir5 = {'site':site_name,'count':request_count,'unique_ip_count':request_unique_count}

        if os.path.exists('database/command5.csv'):
            with open('database/command5.csv', 'a') as f:
                writer = csv.writer(f)
                writer.writerows(log_info)
        else:
            with open('database/command5.csv', 'a') as f:
                log_info.insert(0,['site','request_count','request_unique_count'])
                writer = csv.writer(f)
                writer.writerows(log_info)

        self.dir5 = dir5

    # get site, request sorted by average timetaken and server name, command 4
    def getMaxRequest(self,full_json):
        try:
            aggregations = full_json['aggregations']
        except KeyError as e:
            print(json.dumps(full_json, indent = 4))
            print('Key error in getServerInfo function')
            sys.exit()

        with open('whitelist/whitelist_below_400') as f:
            whitelist_2xx = [line.strip() for line in f.readlines()]

        while '' in whitelist_2xx:whitelist_2xx.remove('')
        while ' ' in whitelist_2xx:whitelist_2xx.remove(' ')
        whitelist_2xx = formatWhitelist(whitelist_2xx)

        if os.path.exists('database/thresholds'):
            with open('database/thresholds') as f:
                thresh_dict = json.loads(f.readline().strip())
                if not thresh_dict or any([False if response in ['4xx','5xx', 'below_4xx'] else True for response in thresh_dict ]):
                    thresh_dict = default_thresh_dict
                    print('empty or missing database/thresholds file using default values, correct format:')
                    print(json.dumps(thresh_dict, indent = 4))
        else:
            thresh_dict = default_thresh_dict
            print('missing database/thresholds file using default values, correct format:')
            print(json.dumps(thresh_dict, indent = 4))

        message4 = ''
        num_aggregations = list(aggregations.keys())[0]
        log_info = []
        for site in aggregations[num_aggregations]['buckets']:
            site_name = site['key']
            site_count = site['doc_count']
            site_other_doc_count = site[list(site.keys())[-1]]['sum_other_doc_count']
            for ip in site[list(site.keys())[-1]]['buckets']:
                ip_type  = ip['key']
                ip_count = ip['doc_count']
                for request in ip[list(ip.keys())[-1]]['buckets']:
                    request_type = request['key']
                    request_count = request['doc_count']
                    log_info.append([site_name, site_count,ip_type,ip_count,request_type,request_count])
                    if 'api' in request_type: continue
                    continue_loop = any([True for whitelist_info in whitelist_2xx if whitelist_info['request'] in request_type and (whitelist_info['site'] == site_name or not(whitelist_info['site'])) and (whitelist_info['ip'] == max_ip or not(whitelist_info['ip']))])
                    if continue_loop: continue

                    if any([word in request_type for word in ['wp-login','wp_login']]):
                        self.command = 2
                        self.query = 'site.raw: '+ site_name +' AND clientip.raw: ' + str(ip_type)
                        self.processJsons()
                        message4 = message4 + 'ip: ' + ip_type + ' |request_count: ' + str(request_count) + '|request: ' + site_name +request_type + self.message2 + '\n'

                    elif (ip_count > self.end*(thresh_dict['below_4xx']['ip']/600) or request_count > self.end*(thresh_dict['below_4xx']['request']/600)) and (ip_count > 1000 or ip_count/site_count > 0.5 ):
                        self.command = 2
                        self.query = 'site.raw: '+ site_name +' AND clientip.raw: ' + str(ip_type)
                        self.processJsons()
                        if request_count/ip_count < 0.5:
                            if self.message2: message4 = message4 + 'ip: ' + ip_type +' |count: ' + str(ip_count )+ ' |site: ' + site_name + self.message2 + '\n'
                        else:
                            if self.message2: message4 = message4 + 'ip: ' + ip_type + ' |count: '+ str(request_count )+ ' |request: ' + site_name + request_type + self.message2 +'\n'

        if os.path.exists('database/command4.csv'):
            with open('database/command4.csv', 'a') as f:
                writer = csv.writer(f)
                writer.writerows(log_info)
        else:
            with open('database/command4.csv', 'a') as f:
                log_info.insert(0,['site','site_count','ip','ip_count','request','request_count'])
                writer = csv.writer(f)
                writer.writerows(log_info)

        self.message4 = message4

    # get request contains average server timetaken and site name for specified query, returns message if response is 500 or timetaken is greater than 10000, command 3
    def getServerInfo(self, full_json):
        try:
            aggregations = full_json['aggregations']
        except KeyError as e:
            print(json.dumps(full_json, indent = 4))
            print('Key error in getServerInfo function')
            sys.exit()

        num_aggregations = list(aggregations.keys())[0]
        all_servers = {}
        log_info = []
        for site in aggregations[num_aggregations]['buckets']:
            site_name = site['key']
            site_count = site['doc_count']
            for response in site[list(site.keys())[2]]['buckets']:
                response_type = response['key']
                response_count = response['doc_count']
                for server in response[list(response.keys())[-1]]['buckets']:
                    server_name = server['key']
                    server_count = server['doc_count']
                    server_timetaken = server['2']['value']
                    log_info.append([site_name, site_count,response_type,response_count,server_name,server_count,server_timetaken])
                    all_servers[server_name] = {'count':server_count, 'timetaken':server_timetaken}

        total_count = 0
        max_server_count  = 0
        all_info = []
        message = ''
        for key, info in all_servers.items():
            all_info.append(key + ', count ' + str(info['count']))
        message = ' |'.join(all_info)

        if os.path.exists('database/command3.csv'):
            with open('database/command3.csv', 'a') as f:
                writer = csv.writer(f)
                writer.writerows(log_info)
        else:
            with open('database/command3.csv', 'a') as f:
                log_info.insert(0,['site','site_count','response_type','response_count','server','server_count','server_timetaken'])
                writer = csv.writer(f)
                writer.writerows(log_info)

        self.message3 = message

    #returns more organization, city, country of an ip, command 2
    def getIpInfo(self, full_json):
        try:
            aggregations = full_json['aggregations']
        except KeyError as e:
            print(json.dumps(full_json, indent = 4))
            print('Key error in getIpInfo function')
            sys.exit()
        log_info = []
        num_aggregations = list(aggregations.keys())[0]

        telegram_message = ''
        for ip in aggregations[num_aggregations]['buckets']:
            ip_type = ip['key']
            for response in ip[list(ip.keys())[-1]]['buckets']:
                response_type = response['key']
                for org in response[list(response.keys())[-1]]['buckets']:
                    org_name = org['key']
                    telegram_message = telegram_message + ' |org name: ' + org_name
                    for country in org[list(org.keys())[-1]]['buckets']:
                        country_name = country['key']
                        telegram_message = telegram_message + ' |location: ' + country_name + ', '
                        for city in country[list(country.keys())[-1]]['buckets']:
                            city_name = city['key']
                            telegram_message = telegram_message + city_name
                            log_info.append([ip_type, response_type, org_name, country_name, city_name])
                break


        if os.path.exists('database/command2.csv'):
            with open('database/command2.csv', 'a') as f:
                writer = csv.writer(f)
                writer.writerows(log_info)
        else:
            with open('database/command2.csv', 'a') as f:
                log_info.insert(0,['ip','response','org','country','city'])
                writer = csv.writer(f)
                writer.writerows(log_info)

        self.message2 = telegram_message

    # returns site, ,response, request and ip, if certain threshold values are met sends telegram message with information, command 1
    def getRequestsIp(self, full_json):
        try:
            aggregations = full_json['aggregations']
        except KeyError as e:
            print(json.dumps(full_json, indent = 4))
            print('Key error in getRequestsIP function')
            sys.exit()
        self.values_printed = False
        num_aggregations = list(aggregations.keys())[0]

        try:
            # 4xx request values to be ignored
            with open('whitelist/whitelist_4xx', 'r') as f:
                whitelist_4xx = [line.strip() for line in f.readlines()]
            while '' in whitelist_4xx:whitelist_4xx.remove('')
            while ' ' in whitelist_4xx:whitelist_4xx.remove(' ')
            whitelist_4xx = formatWhitelist(whitelist_4xx)

            # 5xx request values to be ignored
            with open('whitelist/whitelist_5xx', 'r') as f:
                whitelist_5xx = [line.strip() for line in f.readlines()]
            while '' in whitelist_5xx:whitelist_5xx.remove('')
            while ' ' in whitelist_5xx:whitelist_5xx.remove(' ')
            whitelist_5xx = formatWhitelist(whitelist_5xx)
        except Exception as e:
            print('Removed whitelist files due to incorrect formatting or missing files')
            if not os.path.exists('whitelist/backup_whitelist_4xx'):
                print('Backup whitelist files exist, delete or recover them in the whitelist directory')
                if os.path.exists('whitelist/whitelist_5xx'):
                    os.rename('whitelist/whitelist_5xx', 'whitelist/backup_whitelist_5xx')
                if os.path.exists('whitelist/whitelist_4xx'):
                    os.rename('whitelist/whitelist_4xx', 'whitelist/backup_whitelist_4xx')
            with open('whitelist/whitelist_5xx', 'w'):
                whitelist_5xx = []
            with open('whitelist/whitelist_4xx', 'w'):
                whitelist_4xx = []

        if os.path.exists('database/thresholds'):
            with open('database/thresholds') as f:
                thresh_dict = json.loads(f.readline().strip())
                if not thresh_dict or any([False if response in ['4xx','5xx', 'below_4xx'] else True for response in thresh_dict ]):
                    thresh_dict = default_thresh_dict
                    print('empty or missing database/thresholds file using default values, correct format:')
                    print(json.dumps(thresh_dict, indent = 4))
        else:
            thresh_dict = default_thresh_dict
            print('missing database/thresholds file using default values, correct format:')
            print(json.dumps(thresh_dict, indent = 4))

        log_info =[]
        full_message = []
        for site in aggregations[num_aggregations]['buckets']:
            site_name = site['key']
            site_count = site['doc_count']
            if 'message repeated' in site_name:
                continue

            all_messages = []
            # Iterate through response
            for response in site[list(site.keys())[-1]]['buckets']:
                response_type = int(response['key'])
                response_count= response['doc_count']
                response_other_doc_count = response[list(response.keys())[-1]]['sum_other_doc_count']

                #Iterate through requests
                seen = {}
                for index, request in enumerate(response[list(response.keys())[-1]]['buckets']):
                    request_type = request['key']
                    request_count = request['doc_count']
                    request_unique_count = request['2-orderAgg']['value']
                    max_ip_count = request[list(request.keys())[2]]['buckets'][0]['doc_count']
                    max_ip = request[list(request.keys())[2]]['buckets'][0]['key']

                    log_info.append([site_name,response_type, response_count, request_type, request_count, request_unique_count, max_ip, max_ip_count])
                    # If values are in whitelisted list continue
                    if response_type < 500:
                        continue_loop = any([True for whitelist_info in whitelist_4xx if whitelist_info['request'] in request_type and (whitelist_info['site'] == site_name or not(whitelist_info['site'])) and (whitelist_info['ip'] == max_ip or not(whitelist_info['ip'])) and (int('0'+whitelist_info['response']) == response_type or not(whitelist_info['response']))])
                    elif response_type >= 500:
                        continue_loop = any([True for whitelist_info in whitelist_5xx if whitelist_info['request'] in request_type and (whitelist_info['site'] == site_name or not(site_name)) and (whitelist_info['ip'] == max_ip or not(max_ip)) and (int('0'+whitelist_info['response']) == response_type or not(response))])

                    if continue_loop:
                        continue

                    # check if anomaly is due to one ip address
                    if int(response_type) <  500:
                        #threshold values to that have to be met to be considered an anomaly for ip response 4xx, edit_threshold
                        if max_ip_count >= max(int(self.end*(thresh_dict['4xx']['ip']/600)), 10) and request_unique_count < thresh_dict['4xx']['request']:
                            # get ip org name and city
                            self.command = 2
                            self.query = 'site.raw: '+ site_name +' AND clientip.raw: ' + str(max_ip) + ' AND response: ' + str(response['key'])
                            self.processJsons()
                            message_ip = 'ip: ' + str(max_ip) + ' |response: ' +str(response_type)+ ' |count: ' +str(max_ip_count) + self.message2  + ' |request: ' +site_name + request['key'] + ' |unique_ip_count: ' + str(request_unique_count)
                            all_messages.append(message_ip)

                    # checks max ip of more than 5xx response
                    elif int(response_type) >= 500:
                        #threshold values to that have to be met to be considered an anomaly for ip response 5xx, edit_threshold
                        if  max_ip_count >= max(int(self.end*(thresh_dict['5xx']['ip']/600)), 5) and request_unique_count < thresh_dict['5xx']['request']:
                            # gets ip org name, city name if values are met
                            self.command = 2
                            self.query =  'site.raw: '+ site_name + ' AND clientip.raw: ' + str(max_ip) + ' AND response: ' + str(response['key'])
                            self.processJsons()
                            message_ip = 'ip: ' + str(max_ip) + ' |response: ' +str(response_type)+ ' |count: ' +str(max_ip_count) + self.message2  + ' |request: ' +site_name + request['key'] + ' |unique_ip_count: ' + str(request_unique_count)
                            all_messages.append(message_ip)

                    # request algorithm gets longest common path between requests
                    split_request = request_type.split('/')[1:]
                    if len(seen) == 0:
                        seen[request_type] = {'shortened': False, 'count': request_count, 'unique_count': request_unique_count}
                        continue
                    for seen_request, seen_count in seen.items():
                        split_seen_request = seen_request.split('/')[1:]
                        if len(split_request) > 0 and len(split_seen_request) > 0 and split_seen_request[0] == split_request[0]:
                            new_request = ''
                            for seen_chunck, chunck in zip(split_seen_request, split_request):
                                if seen_chunck == chunck:
                                    new_request = new_request+'/' +chunck
                                else:
                                    break
                            break

                        else:
                            new_request = None
                    if new_request:
                        new_count = seen.pop(seen_request)
                        seen[new_request] = {'shortened': True, 'count': request_count+new_count['count'],'unique_count': request_unique_count + new_count['unique_count']}
                    else:
                        seen[request_type] = {'shortened': False, 'count': request_count, 'unique_count': request_unique_count}


                # looks through seen dict to determine anomalies
                message_xxx = ''
                title_xxx  = 'site: ' + site_name +' response: ' + str(response_type) + '\n'
                for request_instance, request_info in seen.items():
                    #threshold values to that have to be met to be considered an anomaly for response 5xx, edit_threshold
                    if response_type >= 500 and request_info['unique_count'] >=  max(self.end*(thresh_dict['5xx']['request']/600), 3) and request_info['count']/response_count > 0.6:
                        if request_info['shortened']:
                            # get unique count and count for shortened request
                            self.command = 5
                            self.query = 'site.raw: ' + site_name + ' AND response: ' + str(response_type) + ' AND request.raw: ' + request_instance.replace('/', '\\\\\/')+'*'
                            self.processJsons()
                            #threshold values that have to be met to be considered an anomaly for response 5xx, edit_threshold
                            if self.dir5.get('unique_ip_count', 0)>= max(self.end*(thresh_dict['5xx']['request']/600), 3) and self.dir5.get('count', 0)/response_count > 0.6:
                                message_xxx =  message_xxx + 'request: ' + request_instance + '/...' + ' |count: ' + str(self.dir5['count'])+' |unique_ip_count: ' + str(self.dir5['unique_ip_count'])+ '\n'
                            # threshold values that have to be met to be considered an anomaly for response_5xx, edit_threshold
                            elif self.dir5.get('unique_ip_count', 0) == 1 and self.dir5.get('count', 0) > max(self.end*(thresh_dict['5xx']['ip']/600), 30):
                                message_xxx =message_xxx+ 'request: ' + request_instance + '/...' + ' |count: ' + str(self.dir5['count'])+' |unique_ip_count: ' + str(self.dir5['unique_ip_count'])+ '\n'
                        else:
                            # append to message the request when unique count is greater or equal to five
                            message_xxx = message_xxx +'request: ' + request_instance  + ' |count: ' + str(request_info['count']) +' |unique_ip_count: ' + str(request_info['unique_count'])+ '\n'

                    #threshold values to that have to be met to be considered an anomaly for response 4xx, edit_threshold
                    elif response_type < 500 and request_info['unique_count'] >= max(self.end*(thresh_dict['4xx']['request']/600), 3):
                        if request_info['shortened']:
                            #get unique count and count for shortened request
                            self.command = 5
                            self.query = 'site.raw: ' + site_name + ' AND response: ' + str(response_type) + ' AND request.raw: ' + request_instance.replace('/', '\\\\\/')+'*'
                            self.processJsons()
                            #threshold values to that have to be met to be considered an anomaly for response 4xx, edit_threshold
                            if self.dir5.get('unique_ip_count', 0)>= max(self.end*(thresh_dict['4xx']['request']/600), 3):
                                message_xxx = message_xxx + 'request: ' + request_instance+ '/...' + ' |count: ' + str(self.dir5['count']) + ' |unique_ip_count: ' + str(self.dir5['unique_ip_count']) +  '\n'
                            elif self.dir5.get('unique_ip_count', 0) == 1 and self.dir5.get('count', 0) > max(self.end*(thresh_dict['4xx']['ip']/600), 50):
                                message_xxx = message_xxx + 'request: ' + request_instance+ '/...' + ' |count: ' + str(self.dir5['count']) + ' |unique_ip_count: ' + str(self.dir5['unique_ip_count']) + '\n'

                        # if request is not shortened
                        else:
                            message_xxx =message_xxx +  'request: ' + request_instance  + ' |count: ' + str(request_info['count']) +' |unique_ip_count: ' + str(request_info['unique_count']) +  '\n'

                # send gathered anomalies
                if message_xxx != '':
                    #Gather server info for 5xx responses
                    if response_type >= 500:
                        self.command = 3
                        self.query = 'site.raw: ' + site_name + ' AND response: ' + str(response_type)
                        self.processJsons()
                    #send telegram message
                    message_xxx = (title_xxx + message_xxx + self.message3 if response_type >= 500 else title_xxx + message_xxx)
                    all_messages.append(message_xxx.strip())

                # check responses for entire site if no anomaly detected
                elif response_type >= 500:
                    self.command = 5
                    self.query = 'site.raw: ' + site_name + ' AND response: ' + str(response_type)
                    self.processJsons()
                    #threshold values to that have to be met to be considered an anomaly for response 5xx, edit_threshold
                    if self.dir5.get('unique_ip_count', 0) >= max(self.end*(thresh_dict['5xx']['site']/600), 3):
                        message_xxx = 'count: ' + str(self.dir5['count']) + ' |unique_count: ' + str(self.dir5['unique_ip_count'])+'\n'
                        self.command = 3
                        self.query = 'site.raw: ' + site_name + ' AND response: ' + str(response_type)
                        self.processJsons()
                        message_xxx = title_xxx + message_xxx + self.message3
                        all_messages.append(message_xxx.strip())

            if all_messages:
                full_message.append('\n'.join(all_messages))

        if full_message:
            self.values_printed = True
            sendTelegramMessage('\n\n'.join(full_message), silent = self.silent)

        if os.path.exists('database/command1.csv'):
            with open('database/command1.csv', 'a') as f:
                writer = csv.writer(f)
                writer.writerows(log_info)
        else:
            with open('database/command1.csv', 'a') as f:
                log_info.insert(0,['site','response','response_count','request','request_count', 'request_unique_count','max_ip', 'max_ip_count'])
                writer = csv.writer(f)
                writer.writerows(log_info)


    # gets every site that ends with .sample_site.net and all the responses of those sites for the last 5 minutes in the form of a date histogram, command 0
    def getSitesResponses(self, full_json, database_today=False):
        try:
            aggregations = full_json['aggregations']
        except KeyError as e:
            print(json.dumps(full_json, indent =4))
            print('Key error in getSiteResponses function')
            sys.exit()

        num_aggregations = list(aggregations.keys())[0]
        sites = {}
        # will read from a file when reusing data
        if self.reuse_data or database_today:
            try:
                df_old = pd.read_csv(self.name, index_col = ['site', 'date'], parse_dates = ['date'])
            except (ValueError, OSError)as e:
                print('error in file gathering new data, please run program again file has been deleted')
                if os.path.exists(self.name):
                    os.remove(self.name)
                sys.exit()
        else:
            df_old = pd.DataFrame()

        all_responses = list(df_old.columns)

        # Generate list of all errors and update old df with new error columns
        for site in aggregations[num_aggregations]['buckets']:
            for date in site[list(site.keys())[-1]]['buckets']:
                for response in date[list(date.keys())[-1]]['buckets']:
                    s_response = str(response['key'])
                    if s_response not in all_responses:
                        all_responses.append(str(s_response))
                        all_responses.sort()
                        if not df_old.empty:
                            df_old[s_response]= None
        if not df_old.empty:
            df_old = df_old[all_responses]

        # Iterate through site
        for site in aggregations[num_aggregations]['buckets']:

            total_site_count = site['doc_count']
            dates = {}
            # Iterate through day
            for date in site[list(site.keys())[-1]]['buckets']:
                total_time_count = date['doc_count']
                responses = dict(zip(all_responses, [None]*len(all_responses)))
                #Iterate through errors
                for response in date[list(date.keys())[-1]]['buckets']:
                    responses[str(response['key'])] = response['doc_count']

                i_date = datetime.datetime.strptime(date['key_as_string'].split(".")[0], '%Y-%m-%dT%H:%M:%S')
                dates[i_date] = responses
            sites[site['key']]=dates

        # Make tuple from dates and values to make df
        tuples = []
        test = []
        for site, dates in sites.items():
            i_site = [site]*len(dates.keys())
            i_dates = list(dates.keys())
            for date, errors in dates.items():
                test.append(list(errors.values()))
            tuples.extend(list(zip(i_site,i_dates)))

        index = pd.MultiIndex.from_tuples(tuples, names=['site','date'])
        df = pd.DataFrame(test,index=index, columns = all_responses)

        # get list of dates in df and remove first and last values, equivalent to dropping not full buckets
        if not self.reuse_data:
            if database_today:
                unique_dates =list(df.index.get_level_values(1).drop_duplicates())
                unique_dates.sort()
                unique_dates = unique_dates[1:-1]
                new_date = unique_dates.pop(-1)
                full_buckets_index =  [any(date == index for date in unique_dates) for index in df.index.get_level_values(level=1)]
                new_buckets_index =  [new_date == index for index in df.index.get_level_values(level=1)]
                df_old_temp  = df.loc[full_buckets_index].copy()
                df_old = pd.concat([df_old,df_old_temp])
                df.sort_index(inplace=True)
                df_old['new'] = False
                df = df.loc[new_buckets_index].copy()
                df['new'] = True
                self.reuse_data = True
            else:
                unique_dates =list(df.index.get_level_values(1).drop_duplicates())
                unique_dates.sort()
                unique_dates = unique_dates[1:-1]
                full_buckets_index =  [any(date == index for date in unique_dates) for index in df.index.get_level_values(level=1)]
                df_old = df.loc[full_buckets_index].copy()
                df_old['new'] = False
                df = pd.DataFrame()

        else:
            unique_dates =list(df.index.get_level_values(1).drop_duplicates())
            unique_dates.sort()
            unique_dates = unique_dates[1:-1]
            full_buckets_index =  [any(date == index for date in unique_dates) for index in df.index.get_level_values(level=1)]
            df = df.loc[full_buckets_index]
            df['new'] = True

        df = pd.concat([df_old,df])
        df =  df[~df.index.duplicated(keep="last")]
        df.sort_index(inplace=True)
        df.fillna(value= {'new':False}, inplace= True)
        df.fillna(value=np.nan, inplace = True)
        cols = [col for col in df.columns if col == 'new']
        df.drop(columns=cols).to_csv(self.name)
        return df

    # execute curl command
    def getJson(self, command):
        if self.ssh:
            # curl via ssh
            #SSH INFO
            try:
                info = {"username": "username",
                        "hostname": "hostname"}
                ssh = paramiko.SSHClient()
                ssh.load_system_host_keys()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(**info)
            except Exception as e:
                raise Exception('Incorrect ssh info update below \"SSH\" INFO tag')

            # Iterates through get request commands and stores outputs
            stdin, stdout, stderr = ssh.exec_command(command)
            try:
                raw_json=stdout.readlines()[0]
            except Exception as e:
                print(e)
                print(stderr)
            ssh.close()
            raw_json = json.loads(raw_json)
            return raw_json
        else:
            # curl without ssh
            command = command.split(' -d ')[1].strip().strip('\'')
            r = requests.get('http://elk.sample_site.net:9200/web-*/_search', headers = {'Content-Type':'application/json'}, data = command)
            try:
                raw_json= r.json()
            except Exception as e:
                print(r.text)

            with open('database/raw_jsons', 'w') as f:
                f.write(str(raw_json))
            return raw_json

    # reads commands file and fills variables correspondingly
    def formatCommands(self):
        #Determines if get request has correct parameters
        if self.end-self.start< 0:
            print('End date is greater than start date')
            sys.exit()
        elif self.start< 0:
            print('Start is negative')
            sys.exit()
        elif self.interval and self.interval>(self.end-self.start):
            print('Date range is too small')
            sys.exit()

        start = str(self.start)+'s'
        end = str(self.end)+'s'
        if self.interval:
            interval = str(self.interval)+'s'
        else:
            interval = '-1s'

        with open('database/commands', 'r') as f:
            commands = f.readlines()

        if self.ssh:
            command = (commands[self.command] % {"interval": interval,"start":"-"+start, "end": end, "query": str(self.query)}).replace("\"", "\\\"").replace("\'", "\"")
        else:
            command = (commands[self.command] % {'interval': interval,"start":"-"+start,"end":end, "query": str(self.query)})
        return command


    # formats get request data and carries out get request based on command
    def processJsons(self):
        timetaken = 0

        #Verify that old data exists, otherwise create new data, assumption made that old data can be used
        if self.command == 0:
            if self.reuse_data and os.path.exists(self.name):
                print('Reusing old data')
                self.start = 0
                self.end = self.interval*2
                command = self.formatCommands()
                start_time = timeit.default_timer()
                raw_jsons = self.getJson(command)
                end_time = timeit.default_timer()
                timetaken = end_time - start_time
                print('Timetaken ' + str(timetaken))
                return self.getSitesResponses(raw_jsons)

            else:
                if os.path.exists(self.name): os.remove(self.name)
                self.reuse_data = False
                print(colored('Not reusing data', 'red'))

                # format command to gather last week information
                self.end = self.interval*loops_thresh + timeparse('7d')
                self.start =timeparse('7d')-self.interval*loops_thresh
                command_last_week = self.formatCommands()
                print("Creating database, last week: Currently getting time frame " + str(self.start)+ "s to " + str(self.end)+'s')

                start_time = timeit.default_timer()
                raw_jsons = self.getJson(command_last_week)
                end_time = timeit.default_timer()
                timetaken = end_time - start_time
                print('Timetaken ' + str(timetaken))
                df = self.getSitesResponses(raw_jsons)

                # format command to gather today information
                self.end = self.interval*loops_thresh
                self.start = 0
                command_this_week = self.formatCommands()
                print("Creating database, today: Currently getting time frame " + str(self.start) + "s to " + str(self.end) + 's')

                start_time = timeit.default_timer()
                raw_jsons = self.getJson(command_this_week)
                end_time = timeit.default_timer()
                timetaken = end_time - start_time
                print('Timetaken ' + str(timetaken))
                return self.getSitesResponses(raw_jsons, database_today = True)

        else:
            command = self.formatCommands()
            raw_jsons = self.getJson(command)

            if self.command == 1:
                self.getRequestsIp(raw_jsons)
            elif self.command == 2:
                self.getIpInfo(raw_jsons)
            elif self.command == 3:
                self.getServerInfo(raw_jsons)
            elif self.command == 4:
                self.getMaxRequest(raw_jsons)
            elif self.command == 5:
                self.getUniqueIp(raw_jsons)
            elif self.command == 6:
                self.getReferer(raw_jsons)
            else:
                print('No function for given command')
                sys.exit()

# detects anomalies from a Get object, processes data and carries out analysis to determine anomalies
def continousGet(command0, plot_errors = False):
    df = command0.processJsons()

    # for 5xx responses drop values that are less than the threshold value
    df_server = df.loc[:, '500':].loc[df['new']].drop(columns='new').sum(level=0)
    df_server_threshold= (10/600)*command0.interval
    df_server = df_server[df_server >= df_server_threshold].dropna(how='all').dropna(axis=1,how='all')

    # for 4xx error use statistics to determine if it should be considered an anomaly
    # error if value is more than 3 standard deviations away from the mean
    df_client_prev = df.loc[:, '400':'499']
    if df_client_prev.empty:
        df_client_errors = pd.DataFrame()
    else:
        df_client = df.loc[:, '400':'499'].loc[df['new']].droplevel(level=1)
        df_client_std = df_client_prev.std(level=0)
        df_client_mean = df_client_prev.mean(level=0)
        df_client_upper = df_client_mean.add(df_client_std*3, fill_value = 0)
        df_client_errors = df_client[df_client.ge(df_client_upper)]
        df_client_errors = df_client_errors[df_client_errors >= 5].dropna(how='all').dropna(axis=1,how='all')

    # for less than 400 responses use drift method
    prev_values = 4
    df_not_errors = df.loc[:, :'399'].loc[df['new']].droplevel(level=1)
    if df_not_errors.empty:
        df_not_errors = pd.DataFrame()
    else:
        df_not_errors_prev = df.loc[:,:'399'].loc[~df['new']]
        df_not_errors_diff= (df_not_errors_prev.groupby(level=0).tail(prev_values).groupby(level=0).diff().mean(level=0))
        df_not_errors_diff = df_not_errors_diff[df_not_errors_diff>0]
        df_not_errors_last = (df_not_errors_prev.groupby(level=0).last())
        df_not_errors_prediction= df_not_errors_last.add(df_not_errors_diff, fill_value=0)
        df_not_errors_prev_std = df_not_errors_prev.std(level=0)
        drift_weight = df_not_errors_prev_std*math.sqrt((1+1/(prev_values-1)))*3
        df_not_errors_upper = df_not_errors_prediction.add(drift_weight, fill_value = 0)
        df_not_errors = df_not_errors[df_not_errors.ge(df_not_errors_upper)]
        df_not_errors = df_not_errors[df_not_errors >= 200].dropna(how='all').dropna(axis=1,how='all')

    # creating dataframe to print and dataframe that contains errors
    df_print = pd.concat([df_not_errors, df_client_errors,df_server])
    df_errors = pd.concat([df_client_errors,df_server])

    if df_print.empty:
        print('No anomalies')
    else:
        print(df_print)
    # plot errors and and errors previous values used as a visual way to determine if statistical analysis is accurate
    if plot_errors and len(list(df_client_errors.index)) > 0:
        graph_count = len(list(df_client_errors.index))
        dimensions = (math.ceil(graph_count/2) if graph_count != 2 else 2)
        fig, axs = plt.subplots(dimensions, dimensions)
        axs = ([axs] if graph_count == 1 else axs.flatten())

        for subplot_count, i in enumerate(list(df_client_errors.index)):
            client_errors_row = df_client_errors.loc[i]
            df_client_prev.loc[i][df_client_errors.columns].plot(ax=axs[subplot_count] , title = i)
            for column in list(client_errors_row.index):

                if str(client_errors_row.loc[column]) !=  'nan':
                    axs[subplot_count].scatter(datetime.datetime.now() ,client_errors_row.loc[column],c = 'b', label = 'error' + str(column))
                    if str(df_client_upper.loc[i][column]) != 'nan':
                        axs[subplot_count].scatter(datetime.datetime.now(), df_client_upper.loc[i][column],c = 'r', label = 'upper' + str(column))
                axs[subplot_count].legend(loc = 'upper left')

        if len(df_client_errors.index) > 0:
            plt.show()

    ## for 2xx and 3xx responses look at timetaken and max ip
    if not df_not_errors.empty:
        command4 = Get(4)
        command4.query = (local_ips + ' AND ' if local_ips else '') + '(site.raw: ' + ' OR '.join(df_not_errors.index) + ')'
        print('Gathering more info for %(query)s'%{'query':command4.query})
        command4.processJsons()
        if command4.message4:
            sendTelegramMessage(command4.message4, chat_id = 1028832668)

    query_string_client = ''
    query_string_server = ''
    if not df_client_errors.empty:
        all_columns = []
        errors_dict = df_client_errors.to_dict()
        for response, sites in errors_dict.items():
            clean_sites= {k: sites[k] for k in sites if not math.isnan(sites[k])}
            sites_query = [site.split('[')[1] if 'message repeated' in site else site for site in clean_sites.keys()]
            if len(sites_query) == 0:
                continue
            site_response = "(" + "site: ("+" OR ".join(sites_query)+ ")" + " AND response: " + str(response) + ")"
            all_columns.append(site_response)

        # creates new Get object to carry out new get request
        query_string_client = '((' + " OR ".join(all_columns) + ') AND !tags: static)'

    if not df_server.empty:
        all_columns = []
        errors_dict = df_server.to_dict()
        for response, sites in errors_dict.items():
            clean_sites= {k: sites[k] for k in sites if not math.isnan(sites[k])}
            sites_query = [site.split('[')[1] if 'message repeated' in site else site for site in clean_sites.keys()]
            if len(sites_query) == 0:
                continue
            site_response = "(" + "site: ("+" OR ".join(sites_query)+ ")" + " AND response: " + str(response) + ")"
            all_columns.append(site_response)
        query_string_server = '(' + ' OR '.join(all_columns)+ ')'

    if query_string_client or query_string_server:
        # creates new Get object to carry out new get request
        command1 = Get(1)
        command1.query= " OR ".join(filter(None, [query_string_server, query_string_client]))
        print('Gathering more info for %(query)s'%{'query':command1.query})
        command1.end = command0.interval*2
        command1.processJsons()

def formatWhitelist(whitelist):
    return [{'request': word.split(',')[0].strip(), 'site': word.split(',')[1].strip(), 'ip':word.split(',')[2].strip(), 'response':word.split(',')[3].strip()} for word in whitelist]

# create command line options
def formatOptions():
    parser = argparse.ArgumentParser(description='Detect anomalies in logs via kibana get requests.')
    parser.add_argument('--interval', '-i', help = 'interval in seconds or hours to determine frequency of get requests and date histogram interval in kibana', default = '300s')
    parser.add_argument('--yes-recycle', '-y', help = 'reuse old stored data, not recommended unless time passed since last run is less than interval/time between executions',dest='recycle' , action='store_true')
    parser.add_argument('--no-recycle', '-n', help = 'don\'t reuse stored data',dest='recycle' , action='store_false')
    parser.add_argument('--lms', '-l', help = 'filter for logs with lms tag', action = 'store_true')
    parser.add_argument('--silent', '-s', help = 'no notifications will show up for ', action = 'store_true')
    parser.add_argument('--ssh', help = 'execute curl via ssh',action = 'store_true')
    parser.set_defaults(recycle=False)
    args = vars(parser.parse_args())
    return args

def main():
    start_time = timeit.default_timer()
    args = formatOptions()
    Get.silent = args['silent']
    Get.ssh = args['ssh']
    command0= Get(0)
    command0.interval =  timeparse(args['interval'])
    command0.reuse_data = args['recycle']
    if args['lms']:
        command0.query = command0.query + ' AND tags.raw: lms'

    log_files = ['command1.csv', 'command2.csv', 'command3.csv', 'command4.csv','command5.csv','command6.csv']
    for log_file in log_files:
        if os.path.exists('database/'+log_file):
            os.remove('database/'+log_file)

    receiveMessage()
    continousGet(command0)
    num_loops = 1

    while True:
        time.sleep(command0.interval)
        receiveMessage()
        if num_loops == loops_thresh*2:
            log_files = ['command1.csv', 'command2.csv', 'command3.csv', 'command4.csv','command5.csv','command6.csv']
            for log_file in log_files:
                if os.path.exists('database/'+log_file):
                    os.remove('database/'+log_file)

            gc.collect()
            command0.reuse_data = False
            continousGet(command0)
            num_loops = 0
        else:
            continousGet(command0)

        num_loops += 1


if __name__ == '__main__':
    main()

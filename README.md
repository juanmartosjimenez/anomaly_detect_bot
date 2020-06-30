Installation: 
git clone git@github.com:juanmartosjimenez/elastic-anomaly.git

python3 -m pip install pandas pytimeparse seaborn paramiko python-dateutil matplotlib

Usage:
If --ssh option is selected, in the file improved.py, find the comment 'SSH INFO', your ssh credentials should be input in the fields below 

To run the program:
python3 improved.py [-h] [--interval INTERVAL] [--yes-recycle] [--no-recycle] [--lms] [--silent] [--ssh]

Modifiying threshold values:
In the file 'database/thresholds' is a dictionary with all the treshold values that must be met in order for something to be considered an anomaly. 

Whitelisting values:
If an anomaly keeps getting detected that is not an anomaly, the value can be added to the whitelisted values files in csv format, updating these files updates the program real time so there is no need to rerun it 
The whitelist files are whitelist_below_400, whitelist_4xx and whitelist_5xx. Each file contains the fields request, site, response and ip, these can be added manually or through telegram. This feature should be used with some precaution because whitelist_4xx request: a, for example, will ignore any 4xx where the response contains the letter a, this can lead to too many request being ignored. The format for telegram messages should start with a file name either whitelist_5xx, whitelist_4xx or whitelist_below_400 and any combination of the fields site,request,response and ip. If a field is not specified, the whitelist value will apply to every value of that field, for example, whitelisting a request with no more information will apply to every response type, ip and site. 
If the whitelist files have incorrect formatting the files will be cleared and the data will be moved to backup files, this will lead to a sudden influx of whitelisted values appearing as anomalies. More information will appear in stdout

Example telegram formating:
/anomaly_detect whitelist_4xx site: sample_site, response: 404  This will ignore any anomaly with the site sample_site and the response 404
/anomaly_detect whitelist_5xx request: /portal/  This will ignore any anomaly where the request contains the substring /portal/
/anomaly_detect whitelist_below_400 site: sample_site, ip: 10.10.10.10  This will ignore any anomaly with the site sample_site and ip 10.10.10.10. Note: For the whitelist_below_400 file the response field is irrelevant as it is not used.


Command line options:
The command line options work like the options for any other program, in order to get help select the option --help, h
--interval, -i the default interval is 5 minutes, this is the interval used in the initial get request, this interval can be changed and all the thresholds will change correspondingly
--yes-reuse-data, -y will reuse data from the file stored in the directory database/
--no-reuse-data, -n will not reuse data from the file, this is the default option
--lms, -l this will add to the initial query 'tags: lms' so all results will be lms related
--silent, -s telegram messages will not be notified to the client
--ssh, telegram will execute get request via ssh

Program explained:
Prerequisites
The program uses data of the previous requested values, however if no previous values are stored the program will gather x times the requested data to create a database, the program will also gather data from 7 days ago to use that in the statistical analysis. Every time the program is run it deletes the old data and creates new data to avoid erroneous results, however this can be overridden with the --yes-reuse-data, -y command line option, this option is only recommended if the time since the last run is less than the date histogram interval, aka 5 minutes.
The saved data can be viewed in the database directory

When the program is run and the prerequisites are met, an initial request for all response counts on all sites in the form of a histogram is carried out with a 5 minute interval for the last 10 minutes, the first and last bucket are dropped to avoid half full buckets
New responses are marked as anomalies if the they are above the upper bound of the statistical method used, there are two methods used standard deviation for responses above 399 and drift for the rest of responses, the data is assumed to be normally distributed.

If responses are marked as anomalies more data will be requested, each response range is filtered accordingly(Note: threshold values are subject to change):
0 to 399: The max ip will be looked at, if the count of a particular request or the overall count exceed the thresholds it will be marked as an anomaly.
400 to 499: The max IP count will be looked at to see if the sudden increase of that particular response is a result of that IP otherwise the requests for those responses will be looked at. An algorithm combines the longest path in common, for example /apple/carrot, /apple/chair, /chair would return /apple/ and /chair/, the counts of the combined paths are added. If the counts for the paths meet the thresholds and does not include the whitelisted values it is reported as an anomaly
500 to 599: The max IP count will be looked at to see if the sudden increase of that particular response is a result of that IP otherwise the requests for those responses will be looked at. An algorithm combines the longest path in common, for example /apple/carrot, /apple/chair, /chair would return /apple/ and /chair/, the counts of the combined paths are added. If the counts for the paths meet the thresholds and the values are not whitelisted it is reported as an anomaly

Files/Directory:
improved.py, file that contains majority of program used to run the program
telegram_api.py, file that contains all telegram api, if the telegram api is changed this file will have to be modified
whitelist/, directory that contains all of the whitelisted values files, whitelist_5xx, whitelist_4xx, whitelist_below_400
database/thresholds contains all threshold values used to determine if value is an anomaly or not
database/commands, file that contains all curl commands to get data from elastic search
database/raw_jsons, contains the most recent get request json received
database/old_update_ids, file that stores last telegram update id to be used as next offset query, used to avoid reading duplicate values
database/command*.csv, file that contains all detected anomalies regardless of whitelist values, used for debugging
database/local_ips, file that contains company ips to be ignored

Coding, basic usage:
Making a request only requires to create a Get object and then to call the function processJsons() with that object, for example:
def main():
    command0 = Get(0)
    command0.processJsons()

The command number corresponds to the line number in the file commands, in order to add more commands add the curl command at the bottom of the file, a method inside the get class has to be created to process this get request

To override the requests queries is as easy as calling the query field, for example
def main():
    command0 = Get(0)
    command0.query = 'tags: lms'
    command0.processJsons()
    print(command5.df) # Calling this will print a nicely presented data table with the gathered data
This will override the default query to the specified query

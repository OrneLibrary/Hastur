# Hastur 

Analyze output of GoPhish with python to produce findings and capture credentials. 

<p align="center">
  <img src="images/phish.png">
</p>

## Install
```
git clone https://github.com/OrneLibrary/hastur
cd hastur
```

## Usage 
```
usage: hastur.py [-h] [-scope abs_path] [-o] [-p] [-dc [N]] [-ic [N]] [-il [N]] [-io [N]] phish_absolute_path

hastur - pull information from GoPhish and request stats or beautify output

positional arguments:
  phish_absolute_path   specify the location of the csv dump from GoPhish

optional arguments:
  -h, --help            show this help message and exit
  -scope abs_path       specify the location of text file with IPs in scope
  -o, --output          output emails and passwords to two txt files (usernames.txt and passwords.txt) in local directory,
                        default is to output to terminal

STATS ARGUMENTS:
  -p, --ptp             return information for PenTestPortal findings
  -dc [N], --domain_creds [N]
                        return top N email domains for users who entered credentials, default is 5
  -ic [N], --ip_creds [N]
                        return top N remote IPs for user who entered credentials, default is 5
  -il [N], --ip_click [N]
                        return top N remote IPs for user who clicked, default is 5
  -io [N], --ip_open [N]
                        return top N remote IPs for user who opened email, default is 5
```                  

## Usage Examples 

1. Return all credentials from CSV dump file named PhishDump.csv to the command line. 
```
$ python3 hastur.py PhishDump.csv
Credentials:
-----------------------------------------
{'email': ['user1@mail.com'], 'password': ['password1'], 'rid': ['wkwfnUG']}
{'email': ['user2@mail.com'], 'password': ['password12'], 'rid': ['ze4b4H0']}
{'email': ['user3@mail.com'], 'password': ['p@ssword1'], 'rid': ['o9idyZN']}
{'email': ['user4@mail.com'], 'password': ['123456789'], 'rid': ['NDjWBLS']}
-----------------------------------------
```
2. Return in-scope credentials from CSV dump file name PhishDump.csv to the command line using scope IPs found in public_ips.txt.
```
$ python3 hastur.py PhishDump.csv -scope public_ips.txt
                IP
0           [IP Address1]
1           [IP Address2]
2           [IP Address3]
Credentials in Scope:
-----------------------------------------
{'email': ['user1@mail.com'], 'password': ['password1'], 'rid': ['wkwfnUG']}
{'email': ['user4@mail.com'], 'password': ['123456789'], 'rid': ['NDjWBLS']}
-----------------------------------------
Full output in Scope:
-----------------------------------------
{'payload': {'email': ['user1@mail.com'], 'password': ['password1'], 'rid': ['wkwfnUG']}, 'browser': {'address': 'x.x.x.x', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'}}
{'payload':{'email': ['user4@mail.com'], 'password': ['123456789'], 'rid': ['NDjWBLS']}, 'browser': {'address': 'x.x.x.x', 'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'}}
-----------------------------------------
```
3. Output all credentials (no matter of scope) to two files in the local directory for use later from the CSV dump file PhishDump.csv. 

```
$ python3 hastur.py PhishDump.csv -o
$ wc -l emails.txt
74 emails.txt
$ wc -l passwords.txt
75 passwords.txt
```
4. Output the findings for PenTestPortal using PhishDump.csv as the CSV dump file. 
```
$ python3 hastur.py PhishDump.py -p
Number of Emails Sent: 1992
Number of Emails Delivered: 1992
Number of Unique Clicks: 167
Click Rate (%): 8.38
Total Number of Clicks: 300
Time to First Click (HH:MM:SS): 0:01:14.617408
Number of Exploited: 56
Length of Campaign (HH:MM:SS): 3 days, 0:47:10.139899
```
5. Return the top 6 email domains that entered credentials from the PhishDump.csv file. 
```
$ python3 hastur.py PhishDump.csv -dc 6
                      count
google.com              120
yahoo.com                28
aol.com                  16
gmail.com                 9
mail.com                  4
verizon.net               4
```
6. Return the top 5 IP addresses for users who opened the email within the PhishDump.csv file. 
```
python3 hastur.py PhishDump.csv -io
                count
[IP Address1]       20
[IP Address2]       18
[IP Address3]       18
[IP Address4]       14
[IP Address5]       12
```
## GoPhish CSV Download Steps
In order to properly utilize ```hastur```, follow the below steps to dump the CSV from GoPhish. 
1. Navigate to GoPhish Server Dashboard and Click on "Campaigns." 

    ![Dashboard](images/dashboard.png?raw=true "Dashboard")

2. Select the appropriate "Campaign." If completed with Phishing Assessment, select "Archived Campaigns". If incomplete, select "Active Campaigns."

    ![Campaign](images/campaign.png?raw=true "Campaigns")

3. Click on "Stats" (looks like a histogram) of the "Campaign." 

    ![Stats](images/stats.png?raw=true "Stats")

4. Click on "Export CSV" within the "Campaign." 

    ![Export](images/export.png?raw=true "Export")

5. Click "Raw Events."

    ![Raw Events](images/rawevents.png?raw=true "Raw Events")

6. Click "Open With" Sublime Text and ensure it is comma seperated. 

    ![Open With](images/saveas.png?raw=true "Open With")

7. Save the CSV in the desired working directory.

## In-Scope IP Address Preparation (Optional)
In order to properly utilize ```hastur``` with the in-scope capabilities, create a txt file modeled like the below. 

ScopeAddresses.txt
```
IP
x.x.x.x
x.x.x.x
x.x.x.x
x.x.x.x
```

Do not use netmasks. Ensure each line is an individual address. Use DeepOne if necessary. 

## Dependencies
Python 3.8.10

Created by: AJ Read 
# Hastur 

Analyze output of GoPhish with python to produce findings and capture credentials. 

<p align="center">
  <img src="images/phish.png">
</p>

## Install
```
git clone https://github.com/OrneLibrary/hastur
cd hastur
pip3 install -r requirements.txt
```

## Usage 
```
usage: hastur.py [-h] [-scope abs_path] [-f] [-dc [N]] [-ic [N]] [-il [N]] [-io [N]] [-n NAME] [-e EMAIL] [-p PASSWORDS] [-c CLICKS] phish_dump

hastur - pull information from GoPhish and request stats or beautify output

positional arguments:
  phish_dump            specify the location of the csv dump from GoPhish, can be single file or directory

optional arguments:
  -h, --help            show this help message and exit
  -scope abs_path       specify the location of text file with IPs in scope

STATS ARGUMENTS:
  specify various statistics from GoPhish

  -f, --findings        return information for findings
  -dc [N], --domain_creds [N]
                        return top N email domains for users who entered credentials, default is 5
  -ic [N], --ip_creds [N]
                        return top N remote IPs for user who entered credentials, default is 5
  -il [N], --ip_click [N]
                        return top N remote IPs for user who clicked, default is 5
  -io [N], --ip_open [N]
                        return top N remote IPs for user who opened email, default is 5

OUTPUT ARGUMENTS:
  request credentials, user clicks, or other information for future use

  -n NAME, --name NAME  request a single file with emails:passwords credentials
  -e EMAIL, --email EMAIL
                        specify a seperate file with only emails that provided credentials
  -p PASSWORDS, --passwords PASSWORDS
                        specify a seperate file with only passwords
  -c CLICKS, --clicks CLICKS
                        output users who clicked link to a file for future use


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
{'email': ['user4@mail.com'], 'password': ['1234567'], 'rid': ['NDjWBLS']}
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
3. Output credentials to a file named output.txt with emails:passwords from GoPhish. 
```
$ python3 hastur.py PhishDump.csv -n output.txt 
```
4. Output the findings using PhishDump.csv as the CSV dump file. 
```
$ python3 hastur.py PhishDump.py -f
Number of Emails Sent: 669
Number of Emails Delivered: 669
Number of Unique Clicks: 602
Click Rate (%): 89.99
Total Number of Clicks: 1052
Time to First Click (HH:MM:SS): 0:21:21.869481
Number of Unique User and Password Combinations Exploited/Submitted Data: 34
Number of Total Users Exploited/Submitted Data: 62
Length of Campaign (HH:MM:SS): 2 days, 20:32:37.902602
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
7. Output passwords and emails from PhishDump.csv to a file name passwords.txt and emails.txt respectively. 
```
$ python3 hastur.py PhishDump.csv -e emails.txt -p passwords.txt
```
8. Return credentials from multiple campaigns within a phish_directory directory to the terminal. 
```
$ python3 hastur.py phish_directory
Credentials:
-----------------------------------------
{'email': ['user1@mail.com'], 'password': ['password1'], 'rid': ['wkwfnUG']}
{'email': ['user2@mail.com'], 'password': ['password12'], 'rid': ['ze4b4H0']}
{'email': ['user3@mail.com'], 'password': ['p@ssword1'], 'rid': ['o9idyZN']}
{'email': ['user4@mail.com'], 'password': ['123456789'], 'rid': ['NDjWBLS']}
{'email': ['user4@mail.com'], 'password': ['1234567'], 'rid': ['NDjWBLS']}
-----------------------------------------
```
9. Output the findings across multiple campaigns within the phish_directory. 
```
$ python3 hastur.py phish_directory -f                                                                                 
Number of Emails Sent: 2469
Number of Emails Delivered: 2469
Number of Unique Clicks: 1233
Click Rate (%): 49.94
Total Number of Clicks: 2233
Time to First Click (HH:MM:SS): 1 day, 22:25:23.496496
Number of Unique User and Password Combinations Exploited/Submitted Data: 130
Number of Total Users Exploited/Submitted Data: 273
Length of Campaign (HH:MM:SS): 2 days, 22:53:20.855733
```
10. Output the findings across multiple campaigns within phish_directory for IPs in scope from livehosts. 
```
$ python3 hastur.py phish_directory -f -scope livehosts.txt                                                                   
Number of Unique Clicks: 19
Unique Click Rate (%): 11.24
Total Number of Clicks: 34
Number of Unique User and Password Combinations Exploited/Submitted Data: 12
Number of Total Users Exploited/Submitted Data: 28
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

6. Save the CSV in the desired working directory.

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
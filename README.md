# PyPhish

Analyze output of GoPhish to find emails, passwords, domains, and/or unique IP addresses. 

## Install
```
git clone https://github.com/OrneLibrary/pyphish
cd pyphish
```

## Usage 
```
usage: pyphish.py [-h] [-scope abs_path] [-o] [-p] [-domain [N]] [-ip [N]] phish_absolute_path

pyphish - pull information from GoPhish and request stats or beautify output

positional arguments:
  phish_absolute_path  specify the location of the csv dump from GoPhish

optional arguments:
  -h, --help           show this help message and exit
  -scope abs_path      specify the location of text file with IPs in scope
  -o, --output         output emails and passwords to two txt files (usernames.txt and passwords.txt) in local
                       directory, default is to output to terminal

STATS ARGUMENTS:
  -p, --ptp            return information for PenTestPortal findings
  -domain [N]          return top N email domains for users who entered credentials, default is 5
  -ip [N]              return top N remote IPs for user who entered credentials, default is 5
```

## GoPhish CSV Download Steps
In order to properly utilize ```pyphish```, follow the below steps to dump the CSV from GoPhish. 
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
In order to properly utilize ```pyphish``` with the in-scope capabilities, create a txt file modeled like the below. 

ScopeAddresses.txt
```
IP
x.x.x.x
x.x.x.x
x.x.x.x
x.x.x.x
```

Do not use netmasks. Ensure each line is an individual address. 

Created by: AJ Read 
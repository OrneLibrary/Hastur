# PyPhish

Analyze output of GoPhish csv dump to find emails, passwords, domains, and/or unique IP addresses. 

## Install
```
git clone https://github.com/OrneLibrary/pyphish
cd pyphish
```

## Usage 
```
usage: pyphish.py [-h] [-scope scope_absolute_path] [-o] [-domain [N]] [-ip [N]] phish_absolute_path

pyphish - pull information from GoPhish and request stats or beautify output

positional arguments:
  phish_absolute_path   specify the location of the csv dump from GoPhish

optional arguments:
  -h, --help            show this help message and exit
  -scope scope_absolute_path
                        specify the location of excel sheet with ips in scope
  -o, --output          output emails and passwords to two txt files (usernames.txt and passwords.txt) in local directory, default is to output to terminal

STATS ARGUMENTS:
  -domain [N]           return top N email domains, default is 5
  -ip [N]               return top N remote IPs, default is 5
```

## GoPhish Download Steps
1. Navigate to GoPhish Server Dashboard and Click on Campaigns. 

![Dashboard](https://raw.github.com/OrneLibrary/pyphish/main/images/dashboard.png)

2. Select the appropriate Campaign. If completed select "Archived Campaigns". If incomplete, select "Active Campaigns."

Created by: AJ Read 
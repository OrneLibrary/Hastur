import pandas as pd
import json
from collections import Counter
import argparse
from csv import reader
import csv
from dateutil import parser
import numpy as np

def main():
    """
    Main function for pyphish
    """
    parser = argparse.ArgumentParser(description='pyphish - pull information from GoPhish and request stats or beautify output')
    parser.add_argument('phish_csv', action='store', help='specify the location of the csv dump from GoPhish',metavar='phish_absolute_path')
    parser.add_argument("-scope", help='specify the location of text file with IPs in scope',metavar='abs_path')
    parser.add_argument("-o","--output",help="output emails and passwords to two txt files (usernames.txt and passwords.txt) in local directory, default is to output to terminal", action="store_true")

    StatsParser=parser.add_argument_group("STATS ARGUMENTS")
    StatsParser.add_argument("-p","--ptp", help="return information for PenTestPortal findings", action='store_true')
    StatsParser.add_argument("-domain", help="return top N email domains for users who entered credentials, default is 5",type=int, const=5,action='store', metavar='N',nargs='?')
    StatsParser.add_argument("-ip", help="return top N remote IPs for user who entered credentials, default is 5",type=int, const=5,action='store',metavar='N',nargs='?')

    args=parser.parse_args()
    
    # Read in the output of gophish
    phish_df=read_phish(args.phish_csv)

    # Print out the credentials in scope 
    if (args.scope): 
        ip_list=read_scope(args.scope)
        creds,full=return_in_scope(phish_df,ip_list)
        if (args.output):
            return_output(creds)
        else:
            print('Credentials in Scope: ')
            print('-----------------------------------------')
            print('\n'.join(map(str,creds)))
            print('-----------------------------------------')
            print('Full output in Scope:')
            print('-----------------------------------------')
            print('\n'.join(map(str,full)))
            print('-----------------------------------------')

    # Print out the domains in GoPhish (stats)
    elif (args.domain):
        d=return_domains(phish_df)
        print(d[:args.domain])
    
    # Print out all IPs in GoPhish (stats)
    elif (args.ip):
        ip_output=return_remote_ip(phish_df)
        print(ip_output[:args.ip]) #create capability to view a certain number (top 5, top 10, top 20)

    # If the PTP stats are requested 
    elif (args.ptp):
        emails_sent,emails_delivered,unique_clicks,rate,total_clicks,time_to_first,expl,length_campaign=ptp_stats(phish_df)
        print(f'Number of Emails Sent: {emails_sent}')
        print(f'Number of Emails Delivered: {emails_delivered}')
        print(f'Number of Unique Clicks: {unique_clicks}')
        print(f'Click Rate (%): {round(rate*100, 2)}') 
        print(f'Total Number of Clicks: {total_clicks}')
        print(f'Time to First Click (HH:MM:SS): {time_to_first}')
        print(f'Number of Exploited: {expl}')
        print(f'Length of Campaign (HH:MM:SS): {length_campaign}')


    # Print out all credentials and output from CSV 
    else:
        all=return_allcreds(phish_df)
        if (args.output):
            return_output(all)
        else: 
            print('Credentials: ')
            print('-----------------------------------------')
            print('\n'.join(map(str,all)))
            print('-----------------------------------------')

def ptp_stats(input_df):
    emails_sent=0
    emails_delivered=0
    total_clicks=0
    users_click=[]
    unique_clicks=0
    rate=0
    expl=0
    expl_users=[]
    for row in input_df.itertuples():
        if row.message == 'Campaign Created':
            campaign_begin=parser.parse(row.time)
        if row.message == 'Email Sent':
            emails_sent=emails_sent+1
            emails_delivered=emails_delivered+1
        if row.message == 'Clicked Link':
            if total_clicks==0:
                first_click=parser.parse(row.time)
            total_clicks=total_clicks+1
            if row.email not in users_click:
                unique_clicks=unique_clicks+1
                users_click.append(row.email)
        if row.message == 'Submitted Data':
            if row.email not in expl_users:
                expl=expl+1
                expl_users.append(row.email)
        last_time=parser.parse(row.time)
    
    rate=unique_clicks/emails_sent
    time_to_first=first_click-campaign_begin
    length_campaign=last_time-campaign_begin

    return emails_sent,emails_delivered,unique_clicks,rate,total_clicks,time_to_first,expl,length_campaign

# Send usernames and emails to username.txt and passwords.txt within local directory 
def return_output(complete_output):
    with open('emails.txt', 'w') as f_email, open('passwords.txt', 'w') as f_pass:
        for line in complete_output:
            emails=str(line['email']).split("\'")[1] #grab the emails 
            passwords=str(line['password']).split("\'")[1] #grab the passwords

            # Write the emails and passwords to the txt files 
            f_email.write(emails + '\n')
            f_pass.write(passwords+'\n')


# Return a list of IPs in scope for the assessment 
def read_scope(input_scope):
    ip_scope = pd.read_csv(input_scope, engine="python")
    print(ip_scope)
    return ip_scope['IP'].tolist()
# Return the phishing results in a Pandas DataFrame 
def read_phish(input_phish):
    row_email=[]
    row_message=[]
    row_details=[]
    row_time=[]
    with open(input_phish, 'r') as read_obj:
        csv_reader = csv.DictReader(read_obj)
        for row in csv_reader:
            row_email.append(row['email'])
            row_time.append(row['time'])
            row_message.append(row['message'])
            row_details.append(row['details'])
    df = pd.DataFrame(list(zip(row_email,row_time,row_message,row_details)),columns =['email','time', 'message','details'])
    df['details'].replace('', np.nan, inplace=True)
    return df

# Return the credentials for users that are in scope 
def return_in_scope(input_df,input_ip_list):
    finalvalid_creds=[]
    finalvalid_full=[]
    input_df.dropna(subset=['details'],inplace=True)
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
        if "email" in row_json['payload'] and "password" in row_json['payload']:
            if row_json['browser']['address'] in input_ip_list and row_json['payload'] not in finalvalid_creds: #pull creds from payload if not already there
                finalvalid_creds.append(row_json['payload'])
                finalvalid_full.append(row_json)

    return list(finalvalid_creds),list(finalvalid_full)

# Return all domains from the GoPhish csv file 
def return_domains(input_df):
    domains=[]
    input_df.dropna(subset=['details'],inplace=True)
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
        if "email" in row_json['payload'] and "password" in row_json['payload']:
            domains.append(str(row_json['payload']['email']).split("\'")[1].split("@")[1]) #pull the domains out of the email
    
    domains_final_df = pd.DataFrame.from_dict(Counter(domains), orient='index')
    domains_final_df = domains_final_df.rename(columns={'index':'domain', 0:'count'}).sort_values(by=['count'],ascending=False)
    return domains_final_df

# Return all IP addresses from the GoPhish csv file 
def return_remote_ip(input_df):
    remote_ip=[]
    input_df.dropna(subset=['details'],inplace=True)
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
        remote_ip.append(row_json['browser']['address'])

    remote_final_df = pd.DataFrame.from_dict(Counter(remote_ip), orient='index')
    remote_final_df = remote_final_df.rename(columns={'index':'ip', 0:'count'}).sort_values(by=['count'],ascending=False)
    return remote_final_df

# Return all credentials in the GoPhish csv file, regardless of in scope or not 
def return_allcreds(input_df):
    all_creds=[]
    input_df.dropna(subset=['details'],inplace=True)
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
        if "email" in row_json['payload'] and "password" in row_json['payload']:
            if row_json['payload'] not in all_creds:
                all_creds.append(row_json['payload'])
    
    return all_creds

if __name__=="__main__":
	try:
		main()
	except Exception as err:
		print(repr(err))

import pandas as pd
import json
from collections import Counter
import argparse
import csv
from dateutil import parser
import numpy as np
import os 
from pathlib import Path
import requests 

def main():
    """
    Main function for hastur
    """
    parser = argparse.ArgumentParser(description='hastur - pull information from GoPhish and request stats or beautify output')
    parser.add_argument("-scope", help='specify the location of text file with IPs in scope',metavar='abs_path')

    """
    Create Subparsers for CSV and API
    """
    subparser=parser.add_subparsers(title='INPUT METHODS',dest='input_arguments',metavar='method [options ..]')
    csvparser=subparser.add_parser('csv',help='pull information from raw data csv file',description='csvparser - a method to analyze the output of the GoPhish through csv')
    apiparser=subparser.add_parser('api',help='pull information directly via GoPhish API',description='apiparser - a method to analyze the output of the GoPhish through the API')

    csvparser.add_argument('phish_csv', action='store', help='specify the location of the csv dump from GoPhish, can be single file or directory',metavar='phish_dump')
    apiparser.add_argument('server',action='store',help='specify GoPhish server',metavar='url')
    apiparser.add_argument('api_key', action='store', help='specify the API key for GoPhish',metavar='api_key')
    apiparser.add_argument('campaign_id', action='store', help='specify the campaign ID from GoPhish',metavar='campaign_id')


    StatsParser=csvparser.add_argument_group("STATS ARGUMENTS",description="specify various statistics from GoPhish")
    StatsParser.add_argument("-f","--findings", help="return information for findings", action='store_true')
    StatsParser.add_argument("-dc", "--domain_creds", help="return top N email domains for users who entered credentials, default is 5",type=int, const=5,action='store', metavar='N',nargs='?')
    StatsParser.add_argument("-ic", "--ip_creds",help="return top N remote IPs for user who entered credentials, default is 5",type=int, const=5,action='store',metavar='N',nargs='?')
    StatsParser.add_argument("-il", "--ip_click",
                             help="return top N remote IPs for user who clicked, default is 5", type=int,
                             const=5, action='store', metavar='N', nargs='?')
    StatsParser.add_argument("-io", "--ip_open",
                             help="return top N remote IPs for user who opened email, default is 5", type=int,
                             const=5, action='store', metavar='N', nargs='?')

    OutParser=csvparser.add_argument_group("OUTPUT ARGUMENTS",description='request credentials, user clicks, or other information for future use')
    OutParser.add_argument('-n','--name',help="request a single file with emails:passwords credentials",action='store')
    OutParser.add_argument('-e','--email',help="specify a seperate file with only emails that provided credentials",action='store')
    OutParser.add_argument('-p','--passwords',help="specify a seperate file with only passwords",action='store')
    OutParser.add_argument('-c','--clicks',help="output users who clicked link to a file for future use",action='store')


    StatsParser=apiparser.add_argument_group("STATS ARGUMENTS",description="specify various statistics from GoPhish")
    StatsParser.add_argument("-f","--findings", help="return information for findings", action='store_true')
    StatsParser.add_argument("-dc", "--domain_creds", help="return top N email domains for users who entered credentials, default is 5",type=int, const=5,action='store', metavar='N',nargs='?')
    StatsParser.add_argument("-ic", "--ip_creds",help="return top N remote IPs for user who entered credentials, default is 5",type=int, const=5,action='store',metavar='N',nargs='?')
    StatsParser.add_argument("-il", "--ip_click",
                             help="return top N remote IPs for user who clicked, default is 5", type=int,
                             const=5, action='store', metavar='N', nargs='?')
    StatsParser.add_argument("-io", "--ip_open",
                             help="return top N remote IPs for user who opened email, default is 5", type=int,
                             const=5, action='store', metavar='N', nargs='?')

    OutParser=apiparser.add_argument_group("OUTPUT ARGUMENTS",description='request credentials, user clicks, or other information for future use')
    OutParser.add_argument('-n','--name',help="request a single file with emails:passwords credentials",action='store')
    OutParser.add_argument('-e','--email',help="specify a seperate file with only emails that provided credentials",action='store')
    OutParser.add_argument('-p','--passwords',help="specify a seperate file with only passwords",action='store')
    OutParser.add_argument('-c','--clicks',help="output users who clicked link to a file for future use",action='store')


    args=parser.parse_args()

    # Download via API
    if str(args.input_arguments)=='api':
        headers={"Authorization":str(args.api_key)}
        r = requests.get(str(args.server) + '/api/campaigns/'+ str(args.campaign_id) + '/results',headers=headers,verify=False)
        phish_df=pd.DataFrame.from_dict(r.json()['timeline'])
        phish_df['details'].replace('', np.nan, inplace=True)
        
    # Read in the output of gophish csv
    elif str(args.input_arguments)=="csv":
        if os.path.isdir(args.phish_csv):
            unsorted_df=pd.DataFrame()
            for filename in os.listdir(args.phish_csv):
                initial_df=read_phish(os.path.abspath(args.phish_csv + "/"+filename))
                if len(unsorted_df)==0:
                    unsorted_df=initial_df
                else: 
                    unsorted_df=pd.concat([unsorted_df,initial_df])
            phish_df=unsorted_df.sort_values(by='time')

        # Read in the single file 
        elif os.path.isfile(args.phish_csv): 
            phish_df=read_phish(args.phish_csv)
        else: 
            print('Invalid input, a file or directory is required.')
            return  
    else: 
        print('Invalid input for either API or CSV')
        return 

    # Print out the credentials in scope 
    if (args.scope): 
        ip_list=read_scope(args.scope)
        if not (args.findings):
            creds,full=return_in_scope(phish_df,ip_list)

           # if requesting output to a file 
            if (args.name):
                return_output(creds,args.name)
            if (args.email):
                return_output_email(creds,args.email)
            if (args.passwords):
                return_output_password(creds,args.passwords)

            print('Credentials in Scope: ')
            print('-----------------------------------------')
            if len(creds)==0:
                print('[No Credentials]')
            else: 
                print('\n'.join(map(str,creds)))
            print('-----------------------------------------')
            print('Full output in Scope:')
            print('-----------------------------------------')
            if len(full)==0:
                print('[No Output]')
            else: 
                print('\n'.join(map(str,full)))
            print('-----------------------------------------')
        else:
            # Requesting findings for in-scope data
            new_phish_df=downselect_df(phish_df,ip_list)
            unique_clicks,rate,total_clicks,unique_expl,total_expl=findings_stats_scope(new_phish_df)

            print(f'Number of Unique Clicks: {unique_clicks}')
            print(f'Unique Click Rate (%): {round(rate*100, 2)}') 
            print(f'Total Number of Clicks: {total_clicks}')
            print(f'Number of Unique User and Password Combinations Exploited/Submitted Data: {unique_expl}')
            print(f'Number of Total Users Exploited/Submitted Data: {total_expl}')         

    # Print out the domains in GoPhish (stats)
    elif (args.domain_creds):
        d=return_domains(phish_df)

        # Print the requested domains
        print(d[:args.domain_creds])

    # Print out all IPs in GoPhish that entered credentials
    elif (args.ip_creds):
        ip_output,_,_=return_remote_ip(phish_df)

        # Print out the requested number of IP addresses that provided credentials
        print(ip_output[:args.ip_creds])

    # Print out all IPs in GoPhish that clicked on the link
    elif (args.ip_click):
        _,_,ip_output=return_remote_ip(phish_df)

        # Print out the requested number of IP addresses that provided credentials
        print(ip_output[:args.ip_click])

    # Print out all IPs in GoPhish that opened the email
    elif (args.ip_open):
        _,ip_output,_=return_remote_ip(phish_df)

        # Print out the requested number of IP addresses that opened the email
        print(ip_output[:args.ip_open])

    # If the findings stats are requested
    elif (args.findings):
        emails_sent,emails_delivered,unique_clicks,rate,total_clicks,time_to_first,unique_expl,total_expl,length_campaign=findings_stats(phish_df)
        print(f'Number of Emails Sent: {emails_sent}')
        print(f'Number of Emails Delivered: {emails_delivered}')
        print(f'Number of Unique Clicks: {unique_clicks}')
        print(f'Unique Click Rate (%): {round(rate*100, 2)}') 
        print(f'Total Number of Clicks: {total_clicks}')
        print(f'Time to First Click (HH:MM:SS): {time_to_first}')
        print(f'Number of Unique User and Password Combinations Exploited/Submitted Data: {unique_expl}')
        print(f'Number of Total Users Exploited/Submitted Data: {total_expl}')
        print(f'Length of Campaign (HH:MM:SS): {length_campaign}')


    # Print out all credentials
    elif (args.clicks):
        return_clicks(phish_df,args.clicks)
    else:
        all_creds=return_allcreds(phish_df)

        # if requesting output to a file 
        if (args.name) or args.email or args.passwords: 
            if (args.name):
                return_output(all_creds,args.name)
            if (args.email):
                return_output_email(all_creds,args.email)
            if (args.passwords):
                return_output_password(all_creds,args.passwords)

        # Otherwise output to the command line
        else:
            print('Credentials: ')
            print('-----------------------------------------')
            if len(all_creds)==0:
                print('[No Credentials]')
            else: 
                print('\n'.join(map(str,all_creds)))
            print('-----------------------------------------')


def findings_stats(input_df):
    """
    Return statistics for emails sent, emails delivered, unique clicks, click rate, total clicks, time to first click, number exploited, and the length of the campaign
    """
    emails_sent=0
    emails_delivered=0
    total_clicks=0
    users_click=[]
    unique_clicks=0
    unique_expl=0
    total_expl=0
    unique_emailpass_users=[] #hold the unique email and password combinations 
    unique_email_users=[] #hold the unique email combinations 
    first_campaign=True
    for row in input_df.itertuples():
        if row.message == 'Campaign Created' and first_campaign:
            campaign_begin=parser.parse(row.time)
            first_campaign=False
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
            row_json=json.loads(row.details)
            if row.email+"--"+str(row_json['payload']['password']) not in unique_emailpass_users:
                unique_expl=unique_expl+1
                unique_emailpass_users.append(row.email+"--"+str(row_json['payload']['password']))
            if row.email not in unique_email_users: 
                total_expl=total_expl+1 
                unique_email_users.append(row.email)
        last_time=parser.parse(row.time)
    
    rate=unique_clicks/emails_sent
    time_to_first=first_click-campaign_begin
    length_campaign=last_time-campaign_begin

    return emails_sent,emails_delivered,unique_clicks,rate,total_clicks,time_to_first,unique_expl,total_expl,length_campaign

def findings_stats_scope(input_df):
    """
    Return statistics for unique clicks, click rate, total clicks, number exploited
    """
    total_clicks=0
    users_click=[]
    unique_clicks=0
    unique_expl=0
    total_expl=0
    unique_emailpass_users=[] #hold the unique email and password combinations 
    unique_email_users=[] #hold the unique email combinations 
    email_open_list=[]
    emails_open=0
    for row in input_df.itertuples():
        if row.message== 'Email Opened':
            if row.email not in email_open_list:
                emails_open=emails_open+1
                email_open_list.append(row.email)
        if row.message == 'Clicked Link':
            total_clicks=total_clicks+1
            if row.email not in users_click:
                unique_clicks=unique_clicks+1
                users_click.append(row.email)
        if row.message == 'Submitted Data':
            row_json=json.loads(row.details)
            if row.email+"--"+str(row_json['payload']['password']) not in unique_emailpass_users:
                unique_expl=unique_expl+1
                unique_emailpass_users.append(row.email+"--"+str(row_json['payload']['password']))
            if row.email not in unique_email_users: 
                total_expl=total_expl+1 
                unique_email_users.append(row.email)
    
    rate=unique_clicks/emails_open

    return unique_clicks,rate,total_clicks,unique_expl,total_expl

def return_clicks(input_df,name):
    """
    Write the user emails that clicked to a file
    """
    user_click_list=[]
    with open(name,'w') as f: 
        for row in input_df.itertuples():
            if row.message == 'Clicked Link' and row.email not in user_click_list:
                f.write(row.email+'\n')
                user_click_list.append(row.email)
            
    
def return_output(complete_output,name):
    """
    Send emails and passwords to file of choice 
    """
    with open(name,'w') as f:
        for line in complete_output:
            emails=str(line['email']).split("\'")[1] #grab the emails 
            passwords=str(line['password']).split("\'")[1] #grab the passwords

            # Write the emails and passwords to the txt files 
            f.write(emails+ ":" + passwords+ '\n')

def return_output_email(complete_output,name):
    """
    Send emails to file of choice 
    """
    with open(name, 'w') as f_email:
        for line in complete_output:
            emails=str(line['email']).split("\'")[1] #grab the emails
            f_email.write(emails + '\n')

def return_output_password(complete_output,name):
    """
    Send passwords to file of choice 
    """
    with open(name, 'w') as f_pass:
        for line in complete_output:
            passwords=str(line['password']).split("\'")[1] #grab the passwords
            f_pass.write(passwords+'\n')

def read_scope(input_scope):
    """
    Read the scoping document and format properly for use with other functions in Hastur
    """
    ip_scope = pd.read_csv(input_scope, engine="python")
    return ip_scope['IP'].tolist()

def read_phish(input_phish):
    """
    Format the input csv into a pandas dataframe
    """
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


def return_in_scope(input_df,input_ip_list):
    """
    Return the credentials for users/email addresses that are in scope
    """
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

def downselect_df(input_df,input_ip_list):
    """
    Downselect the input dataframe to only contain in-scope IPs
    """
    scope_list=[]
    input_df.dropna(subset=['details'],inplace=True)
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
        if row_json['browser']['address'] in input_ip_list:
            scope_list.append(row)
    return pd.DataFrame(scope_list)

def return_domains(input_df):
    """
    Return the emails domains for users/email addresses
    """
    unique_emails=[]
    domains_creds=[]
    input_df.dropna(subset=['details'],inplace=True)
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
        if row.message == "Submitted Data":
            domain=str(row_json['payload']['email']).split("\'")[1].split("@")[1] #pull domain from email 
            if row.email not in unique_emails: 
                domains_creds.append(domain) 
                unique_emails.append(row.email) 
    domains_final_df = pd.DataFrame.from_dict(Counter(domains_creds), orient='index')
    domains_final_df = domains_final_df.rename(columns={'index':'domain', 0:'count'}).sort_values(by=['count'],ascending=False)
    return domains_final_df


def return_remote_ip(input_df):
    """
    Return IP address statistics based on users who submitted data, clicked the link, and opened the email
    """
    unique_emails_submit=[] 
    unique_emails_click=[]
    unique_emails_open=[]
    remote_ip=[]
    remote_ip_open=[]
    remote_ip_click=[]
    input_df.dropna(subset=['details'],inplace=True)
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
       
        if row.message == "Submitted Data" and (row.email not in unique_emails_submit):
            remote_ip.append(row_json['browser']['address'])
            unique_emails_submit.append(row.email)
        if row.message == "Clicked Link" and row.email not in unique_emails_click:
            remote_ip_click.append(row_json['browser']['address'])
            unique_emails_click.append(row.email)
        if row.message == "Email Opened" and row.email not in unique_emails_open:
            remote_ip_open.append(row_json['browser']['address'])
            unique_emails_open.append(row.email)

    remote_final_df = pd.DataFrame.from_dict(Counter(remote_ip), orient='index')
    remote_final_df = remote_final_df.rename(columns={'index':'ip', 0:'count'}).sort_values(by=['count'],ascending=False)

    remote_final_df_open = pd.DataFrame.from_dict(Counter(remote_ip_open), orient='index')
    remote_final_df_open = remote_final_df_open.rename(columns={'index':'ip', 0:'count'}).sort_values(by=['count'],ascending=False)

    remote_final_df_click = pd.DataFrame.from_dict(Counter(remote_ip_click), orient='index')
    remote_final_df_click = remote_final_df_click.rename(columns={'index':'ip', 0:'count'}).sort_values(by=['count'],ascending=False)

    return remote_final_df,remote_final_df_open,remote_final_df_click

def return_allcreds(input_df):
    """
    Return all credentials, regardless of scope
    """
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

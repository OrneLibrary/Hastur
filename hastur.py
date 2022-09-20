import pandas as pd
import json
from collections import Counter
import argparse
import csv
from dateutil import parser
import numpy as np
import os 
from pathlib import Path

def main():
    """
    Main function for hastur
    """
    parser = argparse.ArgumentParser(description='hastur - pull information from GoPhish and request stats or beautify output')
    parser.add_argument('phish_csv', action='store', help='specify the location of the csv dump from GoPhish, can be single file or directory',metavar='phish_dump')
    parser.add_argument("-scope", help='specify the location of text file with IPs in scope',metavar='abs_path')

    StatsParser=parser.add_argument_group("STATS ARGUMENTS",description="specify various statistics from GoPhish")
    StatsParser.add_argument("-f","--findings", help="return information for findings", action='store_true')
    StatsParser.add_argument("-dc", "--domain_creds", help="return top N email domains for users who entered credentials, default is 5",type=int, const=5,action='store', metavar='N',nargs='?')
    StatsParser.add_argument("-ic", "--ip_creds",help="return top N remote IPs for user who entered credentials, default is 5",type=int, const=5,action='store',metavar='N',nargs='?')
    StatsParser.add_argument("-il", "--ip_click",
                             help="return top N remote IPs for user who clicked, default is 5", type=int,
                             const=5, action='store', metavar='N', nargs='?')
    StatsParser.add_argument("-io", "--ip_open",
                             help="return top N remote IPs for user who opened email, default is 5", type=int,
                             const=5, action='store', metavar='N', nargs='?')

    OutParser=parser.add_argument_group("OUTPUT ARGUMENTS",description='request credentials, user clicks, or other information for future use')
    OutParser.add_argument('-n','--name',help="request a single file with emails:passwords credentials",action='store')
    OutParser.add_argument('-e','--email',help="specify a seperate file with only emails that provided credentials",action='store')
    OutParser.add_argument('-p','--passwords',help="specify a seperate file with only passwords",action='store')
    OutParser.add_argument('-c','--clicks',help="output users who clicked link to a file for future use",action='store')

    args=parser.parse_args()

    # Read in the output of gophish csv
    if os.path.isdir(args.phish_csv):
        phish_df=pd.DataFrame()
        for filename in os.listdir(args.phish_csv):
            initial_df=read_phish(os.path.abspath(args.phish_csv + "/"+filename))
            if len(phish_df)==0:
                phish_df=initial_df
            else: 
                phish_df=pd.concat([phish_df,initial_df])

    # Read in the single file 
    elif os.path.isfile(args.phish_csv): 
        phish_df=read_phish(args.phish_csv)
    else: 
        print('Invalid input, a file or directory is required.')
        return  

    # Print out the credentials in scope 
    if (args.scope): 
        ip_list=read_scope(args.scope)
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
        print('\n'.join(map(str,creds)))
        print('-----------------------------------------')
        print('Full output in Scope:')
        print('-----------------------------------------')
        print('\n'.join(map(str,full)))
        print('-----------------------------------------')

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
        print(f'Click Rate (%): {round(rate*100, 2)}') 
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
            row_json=json.loads(row.details)
            if row.email+"--"+str(row_json['payload']['password']) not in expl_users:
                unique_expl=unique_expl+1
                expl_users.append(row.email+"--"+str(row_json['payload']['password']))
            total_expl=total_expl+1 
        last_time=parser.parse(row.time)
    
    rate=unique_clicks/emails_sent
    time_to_first=first_click-campaign_begin
    length_campaign=last_time-campaign_begin

    return emails_sent,emails_delivered,unique_clicks,rate,total_clicks,time_to_first,unique_expl,total_expl,length_campaign

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
    print(ip_scope)
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


def return_domains(input_df):
    """
    Return the emails domains for users/email addresses that are in scope
    """
    domains_creds=[]
    input_df.dropna(subset=['details'],inplace=True)
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
        if row.message == "Submitted Data":
            domains_creds.append(str(row_json['payload']['email']).split("\'")[1].split("@")[1]) #pull the domains out of the email
    domains_final_df = pd.DataFrame.from_dict(Counter(domains_creds), orient='index')
    domains_final_df = domains_final_df.rename(columns={'index':'domain', 0:'count'}).sort_values(by=['count'],ascending=False)
    return domains_final_df


def return_remote_ip(input_df):
    """
    Return IP address statistics based on users who submitted data, clicked the link, and opened the email
    """
    remote_ip=[]
    remote_ip_open=[]
    remote_ip_click=[]
    input_df.dropna(subset=['details'],inplace=True)
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
        if row.message == "Submitted Data":
            remote_ip.append(row_json['browser']['address'])
        if row.message == "Clicked Link":
            remote_ip_click.append(row_json['browser']['address'])
        if row.message == "Email Opened":
            remote_ip_open.append(row_json['browser']['address'])

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

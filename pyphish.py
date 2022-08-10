import pandas as pd
import json
from collections import Counter
import argparse
from csv import reader
import csv

def main():
    """
    Main function for pyphish
    """
    parser = argparse.ArgumentParser(description='pyphish - pull information from GoPhish and request stats or beautify output')
    parser.add_argument('phish_csv', action='store', help='specify the location of the csv dump from GoPhish',metavar='phish_absolute_path')
    parser.add_argument("-scope", help='specify the location of excel sheet with ips in scope',metavar='scope_absolute_path')
    parser.add_argument("-o","--output",help="output emails and passwords to two txt files (usernames.txt and passwords.txt) in local directory, default is to output to terminal", action="store_true")

    StatsParser=parser.add_argument_group("STATS ARGUMENTS")
    StatsParser.add_argument("-domain", help="return top N email domains for users who enter payload, default is 5",type=int, const=5,action='store', metavar='N',nargs='?')
    StatsParser.add_argument("-ip", help="return top N remote IPs for user who enter payload, default is 5",type=int, const=5,action='store',metavar='N',nargs='?')

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
            print('\n'.join(map(str,creds)))
            print('\n'.join(map(str,full)))

    # Print out the domains in GoPhish (stats)
    elif (args.domain):
        d=return_domains(phish_df)
        print(d[:args.domain])
    
    # Print out all IPs in GoPhish (stats)
    elif (args.ip):
        ip_output=return_remote_ip(phish_df)
        print(ip_output[:args.ip]) #create capability to view a certain number (top 5, top 10, top 20)

    # Print out all credentials and output from CSV 
    else:
        all=return_allcreds(phish_df)
        if (args.output):
            return_output(all)
        else: 
            print('\n'.join(map(str,all)))

# Send usernames and emails to username.txt and passwords.txt within local directory 
def return_output(complete_output):
    with open('emails.txt', 'w') as f_email, open('passwords.txt', 'w') as f_pass:
        for line in complete_output:
            emails=str(line['email']).split("\'")[1] #grab the emails 
            passwords=str(line['password']).split("\'")[1] #grab the passwords

            # Write the emails and passwords to the txt files 
            f_email.write(emails)
            f_email.write('\n')
            f_pass.write(passwords)
            f_pass.write('\n')

# Return a list of IPs in scope for the assessment 
def read_scope(input_scope):
    ip_scope=pd.read_excel(input_scope)
    return ip_scope['IP'].tolist()

# Return the phishing results in a Pandas DataFrame 
def read_phish(input_phish):
    row_email=[]
    row_message=[]
    row_details=[]
    with open(input_phish, 'r') as read_obj:
        csv_reader = csv.DictReader(read_obj)
        for row in csv_reader:
            if row['message'] != 'Email Sent':
                row_email.append(row['email'])
                row_message.append(row['message'])
                row_details.append(row['details'])
    df = pd.DataFrame(list(zip(row_email,row_message,row_details)),columns =['email', 'message','details']).iloc[1: , :]
    return df.dropna(subset=['details'])
    #return df

# Return the credentials for users that are in scope 
def return_in_scope(input_df,input_ip_list):
    finalvalid_creds=[]
    finalvalid_full=[]
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
    for row in input_df.itertuples():
        row_json=json.loads(row.details)
        remote_ip.append(row_json['browser']['address'])

    remote_final_df = pd.DataFrame.from_dict(Counter(remote_ip), orient='index')
    remote_final_df = remote_final_df.rename(columns={'index':'ip', 0:'count'}).sort_values(by=['count'],ascending=False)
    return remote_final_df

# Return all credentials in the GoPhish csv file, regardless of in scope or not 
def return_allcreds(input_df):
    all_creds=[]
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

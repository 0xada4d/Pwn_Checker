#!/usr/bin/python3

import ssl,sys,csv,argparse
from multiprocessing import Pool
#from progress.bar import Bar
import urllib.request


# Command line arguments

parser = argparse.ArgumentParser(description="Check a list of passwords against the HiBP API.")
parser.add_argument('passlist', metavar='PASSLIST',
        help='List of passwords to check for pwnage.')
parser.add_argument('--threads', '-t', type=int,
        default=1, choices=[1, 3, 5, 7, 10, 12, 15, 30],
        help='Number of concurrent threads to run (default 1).')
parser.add_argument('--outfile', '-o',
        default="pwned_list.csv",
        help='Name of CSV file in which store pwned passwords (default pwned_list.csv).')
args = parser.parse_args()

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS)
DiscoveredPW = []
TestPasswords = []
urlpath = "https://api.pwnedpasswords.com/pwnedpassword/"

with open(args.passlist) as input_file:
    for i,line in enumerate(input_file):
        TestPasswords.append(line.strip())


def getResponseCode(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        con = urllib.request.urlopen(req, context=ssl_context)
        return con.getcode(), url.split("/")[-1]
    except urllib.error.HTTPError as e:
        return 404, "dud"

pool = Pool(processes=args.threads)
print('[-] Commencing HiBP check for list ' + args.passlist + ' with ' + str(args.threads) + ' concurrent threads...')
for code, password in pool.imap_unordered(getResponseCode, [(urlpath + pw) for pw in TestPasswords]):
    if (code == 200):
        DiscoveredPW.append(password)

with open(args.outfile,'w') as f:
    writer = csv.writer(f)
    for p in DiscoveredPW:
        writer.writerow([p])

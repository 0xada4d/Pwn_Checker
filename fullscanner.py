#!/usr/bin/env python3 
import socket,sys,os,argparse
from multiprocessing import Pool  
from progress.bar import Bar #pip3 install progress

open_ports = []
progress_bar = Bar('[-] Progress:', max=65535)

# Define command line arguments for use upon execution

parser = argparse.ArgumentParser(description="Scan all ports on a target IP, and then pass the list of open ports to nmap for version scanning.")
parser.add_argument('target', metavar='TARGET',
        help='IP of the target host.')
parser.add_argument('--threads', '-t', type=int,
        default=250, choices=[1, 50, 100, 250, 300, 500, 750, 1000],
        help='Number of concurrent threads to run (default 250).')
parser.add_argument('--outfile', '-o',
        default="scan_output.txt",
        help='Name of file in which store nmap version scan output (default scan_output.txt).')
parser.add_argument('--high_port', '-p', type=int,
        default=65535,
        help='Enter number of highest port to scan (default=65535).')
parser.add_argument('--low_port', '-l', type=int,
        default=1,
        help='Enter number of lowest port to scan (default=1).')
args = parser.parse_args()

# Function called for each port, if connection is successful, add the port to the open_ports list

def scanip(host): 
    target_ip,port = host 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
    sock.settimeout(2) 
    try: 
        sock.connect((target_ip, port)) 
        sock.close() 
        return port, True 
    except(socket.timeout, socket.error): 
        return port, False 

# Set target, number of threads, output file,
# low and high port - arguments pulled from command line options

target_ip = args.target
num_threads = args.threads
o_file = args.outfile
low_port = args.low_port
high_port = args.high_port

# Start the actual scan

ports = range(low_port, high_port + 1) 
pool = Pool(processes=num_threads) 
print('[-] Commencing port scan for host ' + target_ip + ' with ' + str(num_threads) + ' concurrent threads...')
for port, status in pool.imap_unordered(scanip, [(target_ip, port) for port in ports]):
    if status:
        open_ports.append(port)
    progress_bar.next()
progress_bar.finish()
print('[--] Port scan complete.')
portlist = ','.join(map(str, open_ports))
print('[--] Detected open ports: ' + portlist)

# Craft input for nmap, and call nmap via os.system()

if (len(portlist) > 0):
    print('[-] Commencing nmap full version scan for detected ports...')
    nmap_string = 'nmap -sSV -A -p %s %s >> scan_output.txt', (portlist, target_ip,)
    os.system(nmap_string)
else:
    sys.exit("No open ports found on " + target_ip)

# Make the output file easier to read (when script is called for many IP's)

os.system('echo "\n\n===========================================================================" >> ' + o_file)
os.system('echo "===========================================================================" >> ' + o_file)
os.system('echo "===========================================================================\n" >> ' + o_file)
print("[--] Nmap scan complete.")
print("[--] Script exiting -- cat ./{output} for results.".format(output=o_file))


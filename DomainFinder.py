import whois
import _thread
import time

# set domain properties
DOMAIN_PREFIX = ""
DOMAIN_SUFFIX = "curve.com"

# read keywords
file = open("positive-words.txt","r")
word_list = file.readlines()
file.close()

# output file
out_file = open("curvelist.txt", "w")


def dnschecker(keywords):
    for word in keywords:
        host = word.strip()
        host = DOMAIN_PREFIX + host + DOMAIN_SUFFIX
        #print ("Checking domain : {}".format(host))
        try:
            whois_chk = whois.whois(host)
            print ("{}  - Not Avaiable".format(host))
        except whois.parser.PywhoisError:
            print ("{}  - AVAIALBE".format(host))
            out_file.write("{}\n".format(host))

hostnames_ln = len(word_list)
start_index = 0


while (True):
    try:
        list_limit = word_list[start_index:start_index+100]
        if (len(list_limit) < 10 ):
            break
        _thread.start_new_thread(dnschecker, (list_limit,))
        thrd_count += 1
        start_index += 100
        time.sleep(2)
    except KeyboardInterrupt:
        out_file.close()
input()
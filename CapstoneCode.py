#!/bin/python3

from dateutil import parser
import sys
import argparse

# Globals
filepath = '/etc/snort/rules/automated.rules'

def writeRule(rule):
    try:
        with open(filepath, 'r') as f:
            data = f
            with open(filepath, 'a') as f:
                if rule not in data:
                    f.write(rule)
    except:
        print('file doesnt exist')

def getTime(timestr):
    return parser.parse(timestr)

def main():
    # Options
    parser = argparse.ArgumentParser(description="cool stuff")
    parser.add_argument('-w', '--write', help='Snort rule write mode.', action='store_true')
    parser.add_argument('-v', '--verbose', help='Display more data', action='store_true')
    options = parser.parse_args(sys.argv[1:])

    # Vars
    failure = 0
    linenum = 0
    timelist = []
    # Parse the file
    with open('auth2.log') as log:
        for line in log:
            linenum += 1
            data_list = line.split()
            process = data_list[4]
            time = data_list[2]
            info = ''

            for word in data_list[5:]:
                info += word + ' '
            if 'sshd' in process:
                # print(f'Found ssh process in line {linenum}')
                if 'Failed password' in info: # Looking for bad password attempts
                    timelist.append(time)
                    aip = info.split()[5] # attacker ip
                    failure += 1 # add up run of failed password attempts
                    if options.verbose:
                        print(f'{failure} line:{linenum} time:{time}')
                else:
                    if (failure >= 3 and str(getTime(timelist[0]) - getTime(timelist[-1])) == '0:00:00') or failure > 10: # checking for bulk of failures or in quick succession
                        print(f'Potential brute force attack detected with {failure} tries')
                        print(f"Recomended snort rule: drop TCP {aip} any -> $HOME_NET 22 (msg: 'Brute force detected'; sid:1;)\n")
                        if options.write: # auto writing the rule if option present
                            writeRule(f"drop TCP {aip} any -> $HOME_NET 22 (msg: 'Brute force detected'; sid:1;)\n")
                            print('Rule Written')
                        failure = 0
                        timelist = [] # resetting run
            else:
                failure = 0

if __name__ == '__main__':
    main()

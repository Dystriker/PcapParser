import sys
import re
import os
from pcapfile import savefile
import xlwt
import numpy as np
import matplotlib.pyplot as plt

def createBarPlot(data):
    print('ok')


def validate_ip(ip_str):
    reg = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    if re.match(reg, ip_str):
        return True
    else:
        return False

def extract_pcap(pcapfile, user_ip_src, user_ip_dest):
    try:
        open_pcap = open(pcapfile, 'rb')
    except IOError:
        print("Le fichier n'existe pas !")
    
    pcap_file = savefile.load_savefile(open_pcap, layers=2, verbose=True)
    packets_ip = pcap_file.packets
    compteur = 0

    if user_ip_src != '' and user_ip_dest != '':
        for i in range(len(packets_ip)):
            if("from b'" + user_ip_src + "' to b'" + user_ip_dest + "'" in str(pcap_file.packets[i].packet.payload)):
                compteur += 1
        if compteur > 0:
            print('From ' + user_ip_src + ' to ' + user_ip_dest + ' x' + str(compteur) + ' fois')
        else:
            print('Aucune donnée trouvée')

    else:
        pair_matches = []
        matches = []
        clean_matches = []
        clean_pairs = re.compile('ipv4 packet from ([^<]* to [^<]*) carrying')
        
        for i in range(len(packets_ip)):
            pair_matches.append(str(pcap_file.packets[i].packet.payload))
        
        for i in pair_matches:
            clean_pair = re.findall(clean_pairs, i)
            if len(clean_pair) > 0:
                matches.append(clean_pair[0].replace('b', '').replace("'", ""))
                tmp = clean_pair[0].replace('to', '').replace('b', '').replace("'", "")
                clean_matches.append(tmp)
        
        results = [[x, matches.count(x)] for x in set(matches)]
        clean_results = [[x, clean_matches.count(x)] for x in set(clean_matches)]

        for i in results:
            print(str(i[0]) + ' -> ' + str(i[1]) + ' fois')
        
        toExport = str(input("Voulez-vous exporter en CSV ? (o/N) "))
        if toExport.lower() == 'o':
            export_as_csv(clean_results)
        else:
            sys.exit(0)

def export_as_csv(results):

    wbk = xlwt.Workbook('utf-8')
    saveFileXLS = os.getcwd() + '/pcap_results.xls'
    headings_font = xlwt.easyxf('font: color-index blue, bold on; align: horiz centre;')
    normal_font = xlwt.easyxf('font: bold off; align: horiz centre')
    sheet0 = wbk.add_sheet('IPs extraites', cell_overwrite_ok=True)
    sheet0.write(0, 0, 'IP Source', headings_font)
    sheet0.write(0, 1, 'IP Destination', headings_font)
    sheet0.write(0, 2, 'Occurences', headings_font)

    for i in range(len(results)):
        ips = results[i][0].split()
        col = 0
        sheet0.write(i + 1, col, ips[0], normal_font)
        col += 1
        sheet0.write(i + 1, col, ips[1], normal_font)
        col += 1
        sheet0.write(i + 1, col, results[i][1], normal_font)
    print('Rapport crée !')
    wbk.save(saveFileXLS)


def getFileName():
    pcap_file = str(input("Veuillez donner le nom du fichier pcap à parser (sans extension) : "))
    pcap_file += ".pcap"
    
    user_custom = str(input("Voulez-vous préciser une IP Source / Destination à rechercher ? (o/N) "))
    if user_custom.lower() == "o":
        user_ip_src = str(input("IP Source : "))
        user_ip_dest = str(input("IP Dest : "))
        if(validate_ip(user_ip_src) and validate_ip(user_ip_dest)):
            extract_pcap(pcap_file, user_ip_src, user_ip_dest)
        else:
            print('Addresses IP non valides !')
            sys.exit(0)
    else:
        extract_pcap(pcap_file, '', '')

def main():
    getFileName()

if __name__ == '__main__':
    main()
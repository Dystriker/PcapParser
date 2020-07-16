import sys
import re
import os.path
from pcapfile import savefile
import xlwt
import matplotlib.pyplot as plt
from datetime import datetime
from PIL import Image

def graphFiltered(data, ipToSearch):

    # SRC PART
    tabSrc = {}
    for result in data:
        if result[0] == ipToSearch:
            tabSrc[result[1]] = result[2]

    if any(tabSrc):
        ipsSrc = []
        numberSrc = []
        for key, value in tabSrc.items():
            ipsSrc.append(key)
            numberSrc.append(value)
    else:
        print("Aucune donnée en IP Source")   

    # DST PART
    tabDst = {}
    for result in data:
        if result[1] == ipToSearch:
            tabDst[result[0]] = result[2]
    
    if any(tabDst):
        ipsDst = []
        numberDst = []
        for key, value in tabDst.items():
            ipsDst.append(key)
            numberDst.append(value)

    else:
        print("Aucune donnée en IP Destination")

    ### DISPLAY 
    if any(tabSrc) and any(tabDst):
        fig, (ax1, ax2) = plt.subplots(1, 2)
        fig.tight_layout(pad=3.0)

        ax1.bar(ipsSrc, numberSrc, color = 'pink')
        ax1.set_ylabel('Occurences')
        ax1.set_title('IP as Source')

        ax2.bar(ipsDst, numberDst, color = 'red')
        ax2.set_ylabel('Occurences')
        ax2.set_title('IP as Destination')

    elif len(tabSrc) > 0 and len(tabDst) <= 0:
        fig, ax1 = plt.subplots()

        ax1.bar(ipsSrc, numberSrc, color = 'pink')
        ax1.set_ylabel('Occurences')
        ax1.set_title('IP as Source')

    elif len(tabDst) > 0 and len(tabSrc) <= 0:
        fig, ax2 = plt.subplots()

        ax2.bar(ipsDst, numberDst, color = 'red')
        ax2.set_ylabel('Occurences')
        ax2.set_title('IP as Destination')

    plt.savefig('filteredGraphs.png', dpi=200)
   
    plt.show()
    

def countSrc(data):
    numberSrc = 0
    tab = {}
    for x in data:
        ipSrc = x[0]
        occurences = x[2]
        if ipSrc in tab:
            oldValue = tab[ipSrc]
            tab[ipSrc] = oldValue + occurences
        else:
            tab[ipSrc] = occurences
    
    return(tab)

def countDst(data):
    numberDst = 0
    tab = {}
    for x in data:
        ipDst = x[1]
        occurences = x[2]
        if ipDst in tab:
            oldValue = tab[ipDst]
            tab[ipDst] = oldValue + occurences
        else:
            tab[ipDst] = occurences
    
    return(tab)

def autopct_format(values):
    def my_format(pct):
        total = sum(values)
        val = int(round(pct*total/100.0))
        return '{v:d}'.format(v=val)
    return my_format

def generate_graph(data):
    nouveauTableau = []
    for i in range(len(data)):
        tmpTableau = []
        tmpTableau += data[i][0].split('  ')
        tmpTableau.append(data[i][1])
        nouveauTableau.append(tmpTableau)

    basicGraphs(nouveauTableau)
    filterGraph = str(input("Voulez-vous un graphique ciblé sur une IP ? (o/N) "))
    if filterGraph.lower() == "o":
        ipFilter = str(input("Quelle est l'IP que vous voulez filtrer ? "))
        graphFiltered(nouveauTableau, ipFilter)

def basicGraphs(data):
    # IP SRC PART
    labelsSrc = []
    occSrc = []
    tabCountSrc = countSrc(data)
    for key, value in tabCountSrc.items():
        labelsSrc.append(key)
        occSrc.append(value)

    # IP DST PART
    labelsDst = []
    occDst = []
    tabCountDst = countDst(data)
    for key, value in tabCountDst.items():
        labelsDst.append(key)
        occDst.append(value)

    # GENERATE CHARTS
    fig, (ax1, ax2) = plt.subplots(2)

    fig.tight_layout(pad=3.0)

    ax1.pie(occSrc,autopct=autopct_format(occSrc), shadow=True, startangle=90)
    ax1.legend(labelsSrc, title="IP SOURCE")
    ax1.axis('equal')
    ax1.set_title("IP'S AS SOURCE")

    ax2.pie(occDst, autopct=autopct_format(occDst), shadow=True, startangle=90)
    ax2.legend(labelsDst, title="IP DESTINATION")
    ax2.axis('equal')
    ax2.set_title("IP'S AS DESTINATION")

    plt.savefig('basicGraphs.png', dpi=200)
    plt.show()


def validate_ip(ip_str):
    reg = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    if re.match(reg, ip_str):
        return True
    else:
        return False

def extract_pcap(pcapfile):
    try:
        open_pcap = open(pcapfile, 'rb')
    except IOError:
        print("Le fichier n'existe pas !")
    
    pcap_file = savefile.load_savefile(open_pcap, layers=2, verbose=True)
    packets_ip = pcap_file.packets
    compteur = 0

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
    
    toGraphics = str(input("Voulez-vous générer des graphiques ? (o/N) "))
    if toGraphics.lower() == 'o':
        generate_graph(clean_results)
        toExport = str(input("Voulez-vous exporter en CSV ? (o/N) "))
        if toExport.lower() == 'o':
            export_as_csv(clean_results)
        else:
            print("Merci d'avoir utilisé notre PcapParser !")
            sys.exit(0)
    else:
        toExport = str(input("Voulez-vous exporter en CSV ? (o/N) "))
        if toExport.lower() == 'o':
            export_as_csv(clean_results)
        else:
            print("Merci d'avoir utilisé notre PcapParser !")
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
    
    ##############
    
    if os.path.exists("basicGraphs.png"):
        sheet1 = wbk.add_sheet('BasicGraphs', cell_overwrite_ok=True)
        imgBasicGraph = Image.open("basicGraphs.png")
        r, g, b, a = imgBasicGraph.split()
        imgBasicGraph = Image.merge("RGB", (r, g, b))
        imgBasicGraph.save('BasicGraphs.bmp')
        sheet1.insert_bitmap('BasicGraphs.bmp', 1, 1)

    if os.path.exists("filteredGraphs.png"):
        sheet2 = wbk.add_sheet('FilteredGraphs', cell_overwrite_ok=True)
        imgFilteredGraph = Image.open("filteredGraphs.png")
        r, g, b, a = imgFilteredGraph.split()
        imgFilteredGraph = Image.merge("RGB", (r, g, b))
        imgFilteredGraph.save('filteredGraphs.bmp')
        sheet2.insert_bitmap('filteredGraphs.bmp', 2, 1)
    

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

    if os.path.exists(pcap_file):
        extract_pcap(pcap_file)
    else:
        print("Le fichier n'existe pas !")
        sys.exit(0)

def saveAndMove():
    dateChaine = ""
    today = datetime.now()
    dateChaine += str(today.day) + "_" + str(today.month) + "_" + str(today.year) + "-" + str(today.hour) + ":" + str(today.minute) + ":" + str(today.second)
    os.mkdir("save_" + dateChaine)

    files = os.listdir(".")
    
    for f in files:
        if(".bmp" in f or ".png" in f or ".xls" in f):
            os.replace(f, "save_" + dateChaine + "/"+ f) 
 
    

def main():
    getFileName()
    saveAndMove()


if __name__ == '__main__':
    main()
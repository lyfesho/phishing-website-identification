#step1: extract HTTP info
import json
import cv2 as cv
import numpy as np
import os
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import maxminddb
import pandas as pd
import time
from sklearn import svm

def json2dict(in_file):
    with open(in_file, 'r') as load_f:
        new_arr = json.load(load_f)
    return new_arr

def addr2dec(addr):
    items = [int(x) for x in addr.split(".")]
    return sum([items[i] << [24, 16, 8][i] for i in range(3)])

#for https
def crawl_host(sub_url_set, host_name):

    url = "https://" + host_name
    sub_url_set.add(url)

    chrome_options = Options()
    chrome_options.add_argument('--headless')
    browser = webdriver.Chrome(options=chrome_options)
    browser.maximize_window()
    try:
        browser.get(url)

        title = browser.find_element_by_xpath("//h1")
        if "index of" in title.text.lower():
            links = browser.find_elements_by_tag_name('a')
            for link in links:
                link_text = link.get_attribute("href")
                if ("http" not in link_text):
                    url_sub = url+link_text
                else:
                    url_sub = link_text

                sub_url_set.add(url_sub)
    except Exception as e:
        print("ERROR : " + str(e))
    finally:
        browser.close()


def url_crawler(json_http_obj, picdata_dir):
    url = json_http_obj["url"]
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    browser = webdriver.Chrome(options=chrome_options)
    browser.set_window_size(1980, 1020)
    
    #Add Alert Bypass
    try:
        browser.switch_to.default_content()
    except UnexpectedAlertPresentException:
        print('Alert Popup')
        alert = browser.switch_to.alert().accept()
        alert.dismiss()
    
    try:
        now_time = time.process_time()
        browser.get(url)
        pic_name = str(now_time)
        pic_path = picdata_dir + pic_name + ".png"
        browser.save_screenshot(pic_path)

        #relation
        picname_url_relation = {}
        picname_url_relation[pic_name] = url
        print(picname_url_relation)
        browser.save_screenshot(pic_path)

        #generate keypoint descriptors
        screenshot = cv.imread(pic_path, 0)
        sift=cv.xfeatures2d.SIFT_create()
        kp, des = sift.detectAndCompute(screenshot, None)
        if (len(kp) >= 1):
            json_http_obj["screenshot"] = des

    except Exception as e:
        print(url)
        print("SCREENSHOT ERROR : " + str(e))
    finally:
        browser.close()
    
    return json_http_obj

def color_convert(img):
    imgInfo = img.shape
    heigh = imgInfo[0]
    width = imgInfo[1]

    gray = cv.cvtColor(img,cv.COLOR_BGR2GRAY)
    dst = np.zeros((heigh,width,1),np.uint8)

    for i in range(0,heigh):
        for j in range(0,width):
            grayPixel = gray[i,j]
            dst[i,j]=255-grayPixel
    return dst

def FLANN(des1, des2):

    FLANN_INDEX_KDTREE=0
    indexParams=dict(algorithm=FLANN_INDEX_KDTREE,trees=5)
    searchParams= dict(checks=50)
    flann=cv.FlannBasedMatcher(indexParams,searchParams)

    matches=flann.knnMatch(des1,des2,k=2)

    matches_num = 0
    matchesMask=[[0,0] for i in range (len(matches))]
    for i, (m,n) in enumerate(matches):
        if m.distance< 0.5*n.distance: 
            matchesMask[i]=[1,0]
            matches_num += 1 
    return matches_num/len(matches)

def logo_match(json_http_obj):
    match_flag = 0
    if "screenshot" not in json_http_obj:
        return match_flag

    for logo_des in total_logo_list:

        sim = FLANN(logo_des, json_http_obj["screenshot"])
        if (sim > sim_threshold):
            match_flag = 1
            break
    return match_flag

def mmdb_lookup(json_http_obj):
    ip = json_http_obj["ip"]
    mmdb_dict = mmdb_reader.get(ip)
    json_http_obj["asn"] = mmdb_dict["ASN"]
    json_http_obj["lat"] = mmdb_dict["LATITUDE"]
    json_http_obj["log"] = mmdb_dict["LONGITUDE"]
    json_http_obj["prefix"] = addr2dec(ip)
    return json_http_obj

def is_legal(json_http_obj, dataframe_legal):
    ip_list_unknown = []
    asn_list_unknown = []
    lat_list_unknown = []
    lon_list_unknown = []
    if (json_http_obj["asn"] == '-' or '_' in json_http_obj["asn"]):
        print("no asn")

    ip_list_unknown.append(json_http_obj['prefix'])
    asn_list_unknown.append(json_http_obj['asn'])
    lat_list_unknown.append(json_http_obj['lat'])
    lon_list_unknown.append(json_http_obj['log'])
    dataframe_unknown = pd.DataFrame({'ip':ip_list_unknown, 'asn':asn_list_unknown, 'lat':lat_list_unknown, 'lon':lon_list_unknown}, columns=["ip", "asn", "lat", "lon"])

    #training data constructure
    dataframe_combined = pd.concat([dataframe_legal, dataframe_unknown])
    X_train = dataframe_legal                #train:positive
    X_unknowns = dataframe_unknown          #unknowns:negative
    X_combined = dataframe_combined          #test:part of positive from train

    #classifier training
    clf = svm.OneClassSVM(nu=nu_val, kernel="rbf", gamma=0.1)
    clf.fit(X_train)

    #predicting
    y_pred_unknowns = clf.predict(X_unknowns)
    return y_pred_unknowns


rawpkt_file = "./test_pkt/1"
whitelist_file = "./whitelist_new.txt"
mmdb_file = "./GeoLite2-City.mmdb"
picdata_dir = "./screenshot/http/"
https_picdata_dir = "./screenshot/https/"
phishing_data_file = "./dataset/phishing_dataset_0912.json"

#parameters
target = "microsoft.com"
sim_threshold = 0.19
nu_val = 0.15

#statistic
http_all = 0
https_all = 0
http_whitelist_filter_cnt = 0
https_whitelist_filter_cnt = 0
form_filter_cnt = 0

identified_http_phishing_set = []
identified_https_phishing_set = []

#performance for different steps
#match
matched_http_url_set = []
matched_https_url_set = []

#-----------------prepare---------------
#whitelist generate
whitelist = []
wl_file = open(whitelist_file)
while 1:
    line = wl_file.readline()
    if not line:
        break
    whitelist.append(line)
wl_file.close()

#construct logo_list
total_logo_list = []
usable_logo_list = []

root_path_logo = "./logo/"       
for root, dirs, files in os.walk(root_path_logo, False):
    if files:
        for line in files:
            filename = root_path_logo + line
            logoImage = cv.imread(filename, 1)
            logoImage_convert=color_convert(logoImage) #template convert
            #find descriptor
            sift=cv.xfeatures2d.SIFT_create()#创建sift检测器
            kp1, des1 = sift.detectAndCompute(logoImage,None)
            kp2, des2 = sift.detectAndCompute(logoImage_convert,None)
            total_logo_list.append(des1)
            total_logo_list.append(des2)

#mmdb load
mmdb_reader = maxminddb.open_database(mmdb_file)

#init legal data
legal_dict = json2dict("legal_ip_set.json")
legal_ip_list = legal_dict[target]

legal_host = []

for ip in legal_ip_list:
    ip_obj = {}
    ip_obj["ip"] = ip
    ip_obj = mmdb_lookup(ip_obj)
    legal_host.append(ip_obj)

ip_list = []
asn_list = []
lat_list = []
lon_list = []

for host_item in legal_host:
    if (host_item['asn'] == '-' or '_' in host_item['asn']):
        continue
    ip_list.append(host_item['prefix'])
    asn_list.append(host_item['asn'])
    lat_list.append(host_item['lat'])
    lon_list.append(host_item['log'])
dataframe_legal = pd.DataFrame({'ip':ip_list, 'asn':asn_list, 'lat':lat_list, 'lon':lon_list}, columns=["ip", "asn", "lat", "lon"])

#-----------------main------------------

src_file = open(rawpkt_file)
line = src_file.readline()

obj_str = "{"

while line:
    if line == "\r\n":
        line = src_file.readline()
        continue
    line_text = line
    line_text = line_text.strip("\r\n").lstrip()

    if "{" == line_text:
        obj_str = "{"
    elif "," == line_text:
        pkt_obj = json.loads(obj_str)

        src_obj = pkt_obj['_source']
        layer_obj = src_obj['layers']


        if ("frame" not in layer_obj.keys()):
            line = src_file.readline()
            continue

        ptcl = layer_obj['frame']['frame.protocols'].split(':')[-1]

        #http response
        if (ptcl == 'http' or ptcl == "data-text-lines"):
            http_all += 1

        if (ptcl == "data-text-lines"):

            #filter0: not response
            if (layer_obj["tcp"]["tcp.srcport"] != "80"):
                line = src_file.readline()
                continue
            if ("http.response_for.uri" not in layer_obj["http"]):
                line = src_file.readline()
                continue

            url = layer_obj["http"]["http.response_for.uri"].replace('\\', '')
            host_name = url.split('/')[2]

            #======FILTER START======
            #filter1: whitelist
            whitelist_flag = 1
            for whitelist_host in whitelist:
                wl_host = whitelist_host.strip("\r\n")
                if wl_host in host_name:
                    http_whitelist_filter_cnt += 1
                    whitelist_flag = 0
                    continue
            if (whitelist_flag == 0):
                line = src_file.readline()
                continue


            #filter2: form
            form_flag = 2
            http_text_data = layer_obj["data-text-lines"]

            for key_line in http_text_data.keys():
                if ("<form " in key_line):
                    form_flag -= 1
                if ("<input " in key_line):
                    form_flag -= 1
                if (form_flag == 0):
                    break
            if (form_flag != 0):
                form_filter_cnt += 1
                line = src_file.readline()
                continue

            #======FILTER END=======
            unknown_http_obj = {}
            unknown_http_obj["ip"] = layer_obj["ip"]["ip.src"]
            unknown_http_obj["url"] = url

            #active crawl URL, obtain screenshot
            unknown_http_obj = url_crawler(unknown_http_obj, picdata_dir)

            #======MATCH START=======
            #with one logo class
            if (logo_match(unknown_http_obj) == 0):
                line = src_file.readline()
                continue
            #======MATCH END======
            matched_http_url_set.append(unknown_http_obj["url"])

            #look up host features
            json_http_obj = mmdb_lookup(unknown_http_obj)

            #======IDENTIFICATION START======
            if (is_legal(unknown_http_obj, dataframe_legal) == -1):
                identified_http_phishing_set.append(unknown_http_obj["url"])
            #======IDENTIFICATION END======


        #https response
        if (ptcl == 'ssl'):
            https_all += 1

            if (layer_obj["tcp"]["tcp.dstport"] != "443"):
                line = src_file.readline()
                continue
            if layer_obj["ssl"] == "Secure Sockets Layer":
                line = src_file.readline()
                continue
            if "ssl.handshake" not in layer_obj["ssl"]["ssl.record"].keys():
                line = src_file.readline()
                continue
            if isinstance(layer_obj["ssl"]["ssl.record"]["ssl.handshake"], str):
                line = src_file.readline()
                continue

            https_host_name = ""

            #filter0: no sni
            have_sni = 0
            for key in layer_obj["ssl"]["ssl.record"]["ssl.handshake"].keys():
                if ("Extension: server_name" in key):
                    key_temp = key
                    if (int(key_temp.split("len=")[1].strip(')')) != 0):
                        https_host_name = layer_obj["ssl"]["ssl.record"]["ssl.handshake"][key]["Server Name Indication extension"]["ssl.handshake.extensions_server_name"]
                        have_sni = 1
                        break
            if (have_sni == 0):
                line = src_file.readline()
                continue
            if (https_host_name == ""):
                line = src_file.readline()
                continue


            #======filter start======
            #filter1: whitelist
            whitelist_flag = 1
            for whitelist_host in whitelist:
                wl_host = whitelist_host.strip("\r\n")
                if wl_host in https_host_name:
                    https_whitelist_filter_cnt += 1
                    whitelist_flag = 0
                    continue
            if (whitelist_flag == 0):
                line = src_file.readline()
                continue
            #======filter over=======

            #crawl URLs
            host2url_set = set()

            crawl_host(host2url_set, https_host_name)

            for url in host2url_set:
                unknown_https_obj = {}
                unknown_https_obj["ip"] = layer_obj["ip"]["ip.dst"]
                unknown_https_obj["url"] = url

                #active crawl URL, obtain screenshot
                unknown_https_obj = url_crawler(unknown_https_obj, https_picdata_dir)

                #======match start=======
                #with one logo class
                if (logo_match(unknown_https_obj) == 0):
                    continue
                #======match end======
                matched_https_url_set.append(unknown_https_obj["url"])

                #look up host features
                json_https_obj = mmdb_lookup(unknown_https_obj)

                #======identification start======
                if (is_legal(unknown_https_obj, dataframe_legal) == -1):
                    identified_https_phishing_set.append(unknown_https_obj["url"])
                #======identification end======

    elif "[" == line_text or "]" == line_text:
        line = src_file.readline()
        continue
    else:
        obj_str += line_text

    line = src_file.readline()

src_file.close()
print("==================================result generation=================================")
with open("./result/matched_http.json", 'w+') as outfile:
    json.dump(matched_http_url_set, outfile, indent=4)
with open("./result/matched_https.json", 'w+') as outfile:
    json.dump(matched_https_url_set, outfile, indent=4)
with open("./result/identifieded_http.json", 'w+') as outfile:
    json.dump(identified_http_phishing_set, outfile, indent=4)
with open("./result/identifieded_https.json", 'w+') as outfile:
    json.dump(identified_https_phishing_set, outfile, indent=4)

print("==================================statistics start==================================")
#-------------statistics-------------
#load ground truth
true_phishing_dict = json2dict(phishing_data_file)
true_http_phishing_url_set = set()
true_https_phishing_url_set = set()

true_http_phishing_website_set = set()
true_https_phishing_website_set = set()

for phishing_item in true_phishing_dict:
    if ("https:" in phishing_item["url"]):
        true_https_phishing_url_set.add(phishing_item["url"])

        host_name = phishing_item["url"].split('/')[2]
        domain_name = host_name.split('.')[-2] + host_name.split('.')[-1]
        true_https_phishing_website_set.add(domain_name)
    
    elif ("http:") in phishing_item["url"]:
        true_http_phishing_url_set.add(phishing_item["url"])

        host_name = phishing_item["url"].split('/')[2]
        domain_name = host_name.split('.')[-2] + host_name.split('.')[-1]
        true_http_phishing_website_set.add(domain_name)


#identified url
unknown_http_url_set = set()
unknown_http_website_set = set()
unknown_https_url_set = set()
unknown_https_website_set = set()
for item in identified_http_phishing_set:
    unknown_http_url_set.add(item)

    host_name = item.split('/')[2]
    domain_name = host_name.split('.')[-2] + host_name.split('.')[-1]
    unknown_http_website_set.add(domain_name)

for item in identified_https_phishing_set:
    unknown_https_url_set.add(item)

    host_name = item.split('/')[2]
    domain_name = host_name.split('.')[-2] + host_name.split('.')[-1]
    unknown_https_website_set.add(domain_name)

#STATISTICS ON WEBPAGE
#1.1 http precision
http_precision_num = 0
for url in unknown_http_url_set:
    if url in true_http_phishing_url_set:
        http_precision_num += 1
print("http precision : " + str(http_precision_num/len(unknown_http_url_set)))
#1.2 http recall
print("http recall : " + str(http_precision_num/len(true_http_phishing_url_set)))

#2.1 https precision
https_precision_num = 0
for url in unknown_https_url_set:
    if url in true_https_phishing_url_set:
        https_precision_num += 1
print("https precision : " + str(https_precision_num/len(unknown_https_url_set)))
#2.2 https recall
print("https recall : " + str(https_precision_num/len(true_https_phishing_url_set)))


#STATISTICS ON WEBSITE
#1.1 http website precision
#1.1 http precision
http_website_precision_num = 0
for domain_name in unknown_http_website_set:
    if domain_name in true_http_phishing_website_set:
        http_precision_num += 1
print("http precision : " + str(http_website_precision_num/len(unknown_http_website_set)))
#1.2 http recall
print("http recall : " + str(http_website_precision_num/len(true_http_phishing_website_set)))

#2.1 https precision
https_website_precision_num = 0
for domain_name in unknown_https_website_set:
    if url in true_https_phishing_website_set:
        https_website_precision_num += 1
print("https precision : " + str(https_website_precision_num/len(unknown_https_website_set)))
#2.2 https recall
print("https recall : " + str(https_website_precision_num/len(true_https_phishing_website_set)))


#STATISTICS ON FILTERING PERFORMANCE
print("total http packet : " + str(http_all))
print("total https packet : " + str(https_all))

print("http whitelist filter : " + str(http_whitelist_filter_cnt))
print("https whitelist filter : " + str(https_whitelist_filter_cnt))

print("http form filter : ") + str(form_filter_cnt)



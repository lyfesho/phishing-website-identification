#crawl from phishtank file to obtain features
import os
import json
import cv2 as cv
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from multiprocessing.pool import Pool
import time
import socket
import maxminddb
import csv
import base64
import numpy as np
import math
import threading
import codecs

#read csv to dict
def csv2dict(in_file,key,value):
    new_dict = {}
    with open(in_file, newline='', encoding='ISO-8859-1') as f:
        reader = csv.reader(f, delimiter=',')
        fieldnames = next(reader)
        reader = csv.DictReader(f, fieldnames=fieldnames, delimiter=',')
        for row in reader:
            new_dict[row[key]] = row[value]
    return new_dict

def addr2dec(addr):
    items = [int(x) for x in addr.split(".")]
    return sum([items[i] << [24, 16, 8][i] for i in range(3)])

def mmdb_lookup(mmdb_reader, json_http_obj):
    ip = json_http_obj["ip"]
    mmdb_dict = mmdb_reader.get(ip)
    json_http_obj["asn"] = mmdb_dict["ASN"]
    json_http_obj["lat"] = mmdb_dict["LATITUDE"]
    json_http_obj["log"] = mmdb_dict["LONGITUDE"]
    json_http_obj["prefix"] = addr2dec(ip)
    return json_http_obj

def url_crawler(target_dict, picdata_dir, htmldata_dir, mmdb_reader, target_dict_new):

    for json_http_obj in target_dict:

        url = json_http_obj["url"]
        target = json_http_obj["target"]

        #host info
        # host = url.split("/")[2]
        # try:
        #     ip = socket.gethostbyname(host)
        # except:
        #     ip = "unknown"
        # json_http_obj["ip"] = ip
        # if ("unknown" == ip):
        #     continue
        # json_http_obj = mmdb_lookup(mmdb_reader, json_http_obj)
        #
        #screenshot
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        browser = webdriver.Chrome(options=chrome_options)
        browser.set_window_size(1980, 1020)


        #Add Alert Bypass
        # try:
        #     browser.switch_to.default_content()
        # except UnexpectedAlertPresentException:
        #     print('Alert Popup')
        #     alert = browser.switch_to.alert().accept()
        #     alert.dismiss()

        try:
            browser.get(url)
            #print("redirect url : " + browser.current_url)

            tid = threading.current_thread().ident
            now_time = time.process_time()
            pic_name = target + "_" + str(tid) + "_" + str(now_time)
            pic_path = picdata_dir + pic_name + ".png"

            picname_url_relation = {}
            picname_url_relation[pic_name] = url
            print(picname_url_relation)
            browser.save_screenshot(pic_path)

            #save html source code for squatphish
            html_text = browser.page_source
            html_file = codecs.open((htmldata_dir + pic_name + ".txt"), 'w+', 'utf-8')
            html_file.write(html_text)

            #img_base64 = browser.get_screenshot_as_base64()
            #img_decode = base64.b64decode(img_base64)
            #img_array = np.fromstring(img_decode, np.uint8)
            #screenshot = cv.imdecode(img_array, 0)

            #generate keypoint descriptors
            screenshot = cv.imread(pic_path, 0)
            sift = cv.xfeatures2d.SIFT_create()
            kp, des = sift.detectAndCompute(screenshot, None)
            if (len(kp) >= 1):
                json_http_obj["screenshot"] = str(des.tolist())

        except Exception as e:
            print(url)
            print("SCREENSHOT ERROR : " + str(e))
        finally:
            browser.close()

        target_dict_new.append(json_http_obj)

def time_write(output_file, target_dict_new4mt, target_dict_new):

    start_time = time.process_time()
    while True:
        now_time = time.process_time()
        if (now_time - start_time > 600):
            start_time = now_time

            for i in range(len(target_dict_new4mt)):
                target_dict_new = np.hstack((target_dict_new, target_dict_new4mt[i]))

            with open(output_file, 'w+') as outfile:
                json.dump(target_dict_new.tolist(), outfile, indent=4)

            target_dict_new = []



if __name__ == '__main__':
    #DEFINE global const
    #right_picdata_dir = './data/pic/right/'
    picdata_dir = './data/pic/'
    htmldata_dir = './data/html/'
    #relation_file = "./relation.txt"
    mmdb_file = "./GeoLite2-City.mmdb"
    csv_file = "verified_online.csv"
    output_file = "phishing_data_pre.json"

    #DEFINE global var
    core_num = 8

    mmdb_reader = maxminddb.open_database(mmdb_file)

    target_dict = []
    target_dict4mt = []
    target_dict_new = []
    target_dict_new4mt = []
    target_statistic = {}

    target_set = {"Facebook", "	Dropbox", "PayPal", "Amazon.com", "Apple", "Microsoft", "Google", "Yahoo"} #skype
    #target_set = {"Microsoft"}
    phishtank_dict = csv2dict(csv_file, 'phish_id', 'url')
    url_target_dict = csv2dict(csv_file, 'phish_id', 'target')

    for phish_id in url_target_dict.keys():
        if url_target_dict[phish_id] not in target_set:
            continue

        target_obj = {}
        target_obj["url"] = phishtank_dict[phish_id]
        target_obj["target"] = url_target_dict[phish_id]
        target_dict.append(target_obj)

        # add to set
        if url_target_dict[phish_id] not in target_statistic:
            target_statistic[url_target_dict[phish_id]] = 1
        else:
            target_statistic[url_target_dict[phish_id]] += 1
    print(sorted(target_statistic.items(), key=lambda d: d[1], reverse=True))
    print("==================================================================")

    #split target into core num
    ele_num = int(math.ceil(len(target_dict) / float(core_num - 1)))
    for i in range (0, len(target_dict), ele_num):
        target_dict4mt.append(target_dict[i:i+ele_num])
        target_dict_new4mt.append([])

    #multithread
    threads = []
    start_time = time.process_time()
    t0 = threading.Thread(target=time_write, args=(output_file, target_dict_new4mt, target_dict_new))
    threads.append(t0)

    for i in range(core_num - 1):
        t = threading.Thread(target=url_crawler,
                             args=(target_dict4mt[i], picdata_dir, htmldata_dir, mmdb_reader, target_dict_new4mt[i]))
        threads.append(t)

    threads[0].setDaemon(True)
    threads[0].start()

    for i in range(core_num - 1):
        threads[i+1].start()

    for i in range(core_num - 1):
        threads[i+1].join()


    for i in range(len(target_dict_new4mt)):
        target_dict_new = np.hstack((target_dict_new, target_dict_new4mt[i]))
    with open(output_file, 'w+') as outfile:
        json.dump(target_dict_new.tolist(), outfile, indent=4)


        #multiprocesses
    # pool = Pool(processes=4)
    # for json_http_obj in target_dict:
    #     res = pool.apply_async(url_crawler, args=(json_http_obj, picdata_dir, mmdb_reader))
    #     target_dict_new.append(res.get())
    # pool.close()
    # pool.join()
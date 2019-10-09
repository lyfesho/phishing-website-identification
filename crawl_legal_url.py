#legal traffic generation
#need to open wireshark
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from queue import Queue
import threading
import time
import codecs

def crawl(url, unvisited_queue, useful_domain_set, picdata_dir, htmldata_dir):
    chrome_options = Options()
    chrome_options.add_argument('--headless')
    browser = webdriver.Chrome(options=chrome_options)
    browser.maximize_window()

    try:
        browser.get(url)

        now_time = time.process_time()
        pic_name = str(now_time)
        pic_path = picdata_dir + pic_name + ".png"

        picname_url_relation = {}
        picname_url_relation[pic_name] = url
        print(picname_url_relation)
        browser.save_screenshot(pic_path)

        # save html source code for squatphish
        html_text = browser.page_source
        html_file = codecs.open((htmldata_dir + pic_name + ".txt"), 'w+', 'utf-8')
        html_file.write(html_text)

        # img_base64 = browser.get_screenshot_as_base64()
        # img_decode = base64.b64decode(img_base64)
        # img_array = np.fromstring(img_decode, np.uint8)
        # screenshot = cv.imdecode(img_array, 0)


        links = browser.find_elements_by_tag_name('a')

        for link in links:
            link_text = link.get_attribute("href")

            if link_text is None:
                continue

            if ("https://" not in link_text):
                new_link = "https://" + link_text.lstrip("//")
            else:
                new_link = link_text

            useful_flag = 0
            host_text = new_link.split("//")[1].split('/')[0]
            for domain in useful_domain_set:
                if domain in host_text:
                    useful_flag = 1
                    break

            if useful_flag == 0:
                continue

            unvisited_queue.put(new_link)
    except Exception as e:
        print("CRAWL ERROR : " + str(e))
    finally:
        browser.close()

def crawl4url(visitedurl_set, unvisited_queue, useful_domain_set, picdata_dir, htmldata_dir):
    while not unvisited_queue.empty():
        url = unvisited_queue.get()
        if url in visitedurl_set:
            continue

        crawl(url, unvisited_queue, useful_domain_set, picdata_dir, htmldata_dir)
        visitedurl_set.add(url)


visitedurl_set = set()
unvisited_queue = Queue()

whitelist_file = "whitelist_new.txt"
brand_name = "paypal"
root_url = "https://www.google.com/search?q=" + brand_name
picdata_dir = "./legaldata/paypal/pic/"
htmldata_dir = "./legaldata/paypal/html/"

useful_domain_set = set()
wl_file = open(whitelist_file)
while 1:
    line = wl_file.readline()
    if not line:
        break
    if brand_name in line:
        wl_host = line.strip("\r\n")
        useful_domain_set.add(wl_host)
wl_file.close()

unvisited_queue.put(root_url)
crawl4url(visitedurl_set, unvisited_queue, useful_domain_set, picdata_dir, htmldata_dir)
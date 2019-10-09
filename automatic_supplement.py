from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import json

def json2dict(in_file):
    with open(in_file, 'r') as load_f:
        new_arr = json.load(load_f)
    return new_arr

def crawl_host(picdata_dir, host_name):

    url = "https://" + host_name
    sub_url_set = set()

    chrome_options = Options()
    chrome_options.add_argument('--headless')
    browser = webdriver.Chrome(options=chrome_options)
    browser.maximize_window()
    try:
        browser.get(url)
        first_pic_path = picdata_dir + host_name + "_root.png"
        browser.save_screenshot(first_pic_path)

        title = browser.find_element_by_xpath("//h1")
        if "index of" in title.text.lower():
            links = browser.find_elements_by_tag_name('a')
            link_cnt = 0
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
    for url_sub in sub_url_set:
        try:
            chrome_options = Options()
            chrome_options.add_argument('--headless')
            browser = webdriver.Chrome(options=chrome_options)
            browser.maximize_window()

            print(url_sub)
            browser.get(url_sub)
            link_cnt += 1
            pic_name = host_name + "_" + str(link_cnt)
            pic_path = picdata_dir + pic_name + ".png"
            browser.save_screenshot(pic_path)
            print(pic_path)
        except Exception as e:
            print("SCREENSHOT ERROR : " + str(e))
        finally:
            browser.close()


picdata_dir = "./https/pic/"
target_dict = json2dict("phishing_dataset_0910.json")
for item in target_dict:
    if ("https" in item["url"]):
        host_name = item["url"].split("/")[2]
        crawl_host(picdata_dir, host_name)
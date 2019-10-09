#constructing phishing dataset after true_phishing_info collected
import os
import json

def json2dict(in_file):
    with open(in_file, 'r') as load_f:
        new_arr = json.load(load_f)
    return new_arr

right_picdata_dir = "./data/pic/right/"
relation_file = "./relation.txt"
output_file = "./phishing_dataset.json"
existed_phishing_dataset_file = "./phishing_dataset.json"
phishing_pre_file = "phishing_data_pre.json"

picdata_set = set()

#first time
target_dict = []
#after first time
#target_dict = json2dict(existed_phishing_dataset_file)

phishing_pre_dict = json2dict(phishing_pre_file)

# true phishing key
for root, dirs, files in os.walk(right_picdata_dir, False):
    if files:
        for line in files:
            if "-" in line:
                key = line.split("-")[1].strip(".png")
            else:
                key = line.strip(".png")
            picdata_set.add(key)

for line in open(relation_file, 'r', encoding='UTF-8'):

    key = line.split("': '")[0].strip("{").strip("'")
    if len(line.split("': '")) == 1:
        continue
    value = line.split("': '")[1].strip("\r\n").strip("\'}")
    if key in picdata_set:
        for item in phishing_pre_dict:
            if ("screenshot" not in item or "ip" not in item):
                continue
            elif ("url" in item):
                if (item["url"] == value):
                    target_dict.append(item)
            else:
                continue

with open(output_file, 'w+') as outfile:
    json.dump(target_dict, outfile, indent=4)
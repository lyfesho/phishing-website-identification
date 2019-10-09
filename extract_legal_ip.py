#after generate legal traffic using crawl legal url
#extract ip set
import json

rawpkt_file = "./legal_ip_wireshark/1"
legal_ip_set = {}
output_file = "legal_ip_set.json"
target_website = {"microsoft.com"}

#too big to be opened
#with open(rawpkt_file, "r") as load_f:
#    pkt_arr = json.load(load_f)

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
        host_name = ""
        #http response
        if (ptcl == 'http'):
            if (layer_obj["tcp"]["tcp.dstport"] != "80"):
                line = src_file.readline()
                continue
            host_name = layer_obj["http"]["http.host"]
        #https response
        elif (ptcl == "ssl"):
            if (layer_obj["tcp"]["tcp.dstport"] != "443"):
                line = src_file.readline()
                continue


            if layer_obj["ssl"] == "Secure Sockets Layer":
                line = src_file.readline()
                continue

            if isinstance(layer_obj["ssl"]["ssl.record"], dict):
                if "ssl.handshake" not in layer_obj["ssl"]["ssl.record"].keys():
                    line = src_file.readline()
                    continue

                if isinstance(layer_obj["ssl"]["ssl.record"]["ssl.handshake"],str):
                    line = src_file.readline()
                    continue
                for key in layer_obj["ssl"]["ssl.record"]["ssl.handshake"].keys():
                    if ("Extension: server_name" in key):
                        key_temp = key
                        if (int(key_temp.split("len=")[1].strip(')')) != 0):
                            host_name = layer_obj["ssl"]["ssl.record"]["ssl.handshake"][key]["Server Name Indication extension"][
                                "ssl.handshake.extensions_server_name"]
                            break
        if host_name == "":
            line = src_file.readline()
            continue


        for target in target_website:
            if (target in host_name):
                if target in legal_ip_set:
                    legal_ip_set[target].add(layer_obj["ip"]["ip.dst"].strip("\'"))
                else:
                    legal_ip_set[target] = set()
                    legal_ip_set[target].add(layer_obj["ip"]["ip.dst"].strip("\'"))

    elif "[" == line_text or "]" == line_text:
        line = src_file.readline()
        continue
    else:
        obj_str = obj_str + line_text

    line = src_file.readline()

src_file.close()

for domain in legal_ip_set.keys():
    temp = legal_ip_set[domain]
    legal_ip_set[domain] = list(temp)

with open(output_file, 'w+') as outfile:
    json.dump(legal_ip_set, outfile, indent=4)
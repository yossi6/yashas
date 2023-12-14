import requests
import json


def get_filename(json_response) -> str:
    return json_response["data"]["attributes"]["meaningful_name"]


def get_filetype(json_response) -> str:
    return json_response["data"]["attributes"]["type_extension"]


def get_hashes(json_response):
    hashes = {}
    hashes["MD5"] = json_response["data"]["attributes"]["md5"]
    hashes["SHA1"] = json_response["data"]["attributes"]["sha1"]
    hashes["SHA256"] = json_response["data"]["attributes"]["sha256"]
    return hashes


def detection_count(json_response) -> int:
    engines = json_response["data"]["attributes"]["last_analysis_results"].items()
    mal_count = 0
    for engine in engines:
        detection = engine[1]["category"]
        if detection == "malicious":
            mal_count += 1
    return mal_count


def main(hash, api_key):
    
    url = f'https://www.virustotal.com/api/v3/files/{hash}'
    ip_url = url + '/relationships/contacted_ips'
    dom_url = url + '/relationships/contacted_domains'
    headers = {"accept": "application/json",
               "x-apikey": api_key}   
    print("sending request to API")
    
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print("[API Call success] File report incoming")
        json_response = json.loads(response.text)

        report = open('report.json', 'w')
        report.write(response.text)

        filename = get_filename(json_response)
        filetype = get_filetype(json_response)
        mal_count = detection_count(json_response)
        file_hashes = get_hashes(json_response)
        print(f"the file \"{filename}\" of type {filetype} was detected in {mal_count} engines")
        print(file_hashes)

    else:
        print('[API Call failed] failed to fetch report')

    ip_response = requests.get(ip_url, headers=headers)
    if ip_response.status_code == 200:
        print("[API Call success] Related ip addresses incoming")

        ip_data = open('ip_data.json', 'w')
        ip_data.write(ip_response.text)

        print('Related IP addresses can be found in ip_data.json file')

    else:
        print('[API Call failed] failed to fetch relatd IP addresses')


    dom_response = requests.get(dom_url, headers=headers)
    if dom_response.status_code == 200:
        print("[API Call success] Related domains incoming")

        dom_data = open('domain_data.json', 'w')
        dom_data.write(dom_response.text)

        print('Related Domains can be found in the domain_data.json file')

    else:
        print('[API Call failed] failed to fetch related domains')


if __name__ == '__main__':
    with open('config.json') as conf:
        config = json.load(conf)

    _hash = config["hash"]
    _apikey = config["api_key"]
    main(_hash, _apikey)
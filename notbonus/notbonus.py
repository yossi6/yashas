import json

def main():
    with open('virustotal.json', 'r') as f:
        vtfile = json.load(f)


    #get file name
    filename = vtfile["attributes"]["meaningful_name"]
    print(filename)

    #get file type
    filetype = vtfile["attributes"]["detectiteasy"]["filetype"]
    print(filetype)

    #get malicious count
    #two methods: 1 is slower but interesting, the other is boring as fuck but faster
    #complex but interesting option, shows coding skill:
    engines = vtfile["attributes"]["last_analysis_results"].items()
    mal_count1 = 0
    for engine in engines:
        detection = engine[1]["category"]
        if detection == "malicious":
            mal_count1 += 1

    #boring option, shows that i can simply read a json file:
    mal_count2 = vtfile["attributes"]["last_analysis_stats"]["malicious"]
    print(mal_count2)
    

    #get hashes in types: MD5, SHA1, SHA256 // this should be a function as well
    hashes = {}
    hashes["MD5"] = vtfile["attributes"]["md5"]
    hashes["SHA1"] = vtfile["attributes"]["sha1"]
    hashes["SHA256"] = vtfile["attributes"]["sha256"]
    print(hashes)

    #get contacted domains // supposed to be in a different api call
    #in this case its appended to the regular report
    rd = vtfile["relationships"]["contacted_domains"]["data"]
    related_domains = [rd[i]["id"] for i in range(len(rd))]
    print(related_domains)
    
    #get contacted domains // supposed to be in a different api call
    #in this case its appended to the regular report
    rip = vtfile["relationships"]["contacted_ips"]["data"]
    related_ips = [rip[i]["id"] for i in range(len(rip))]
    print(related_ips)


if __name__ == '__main__':
    main()
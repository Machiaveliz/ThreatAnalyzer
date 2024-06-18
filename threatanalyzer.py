import argparse
import requests
import json
import pandas as pd
import re
import sys
import base64
from openpyxl import Workbook
from openpyxl.chart import BarChart, Reference
from datetime import datetime, timedelta

def extract_whois_info(whois_data, patterns):
    for pattern in patterns:
        match = re.search(pattern, whois_data, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return "Not Found!"

def print_progress_bar(iteration, total, start_time, length=50, fill='█'):
    percent = ("{0:.1f}").format(100 * (iteration / float(total)))
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    elapsed_time = datetime.now() - start_time
    estimated_total_time = elapsed_time / iteration * total if iteration > 0 else timedelta(0)
    remaining_time = estimated_total_time - elapsed_time
    elapsed_str = str(elapsed_time).split('.')[0]
    remaining_str = str(remaining_time).split('.')[0]
    sys.stdout.write(f'\rProgress: |{bar}| {percent}% Complete | Elapsed Time: {elapsed_str} | Remaining Time: {remaining_str} ')
    sys.stdout.flush()
    if iteration == total:
        print()

def fetch_ip_data(ip, index, total_ips, start_time, threshold, results, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    parse_json = json.loads(response.text)

    result = {'IP': ip}

    try:
        malicious_count = parse_json['data']['attributes']['last_analysis_stats']['malicious']
    except KeyError:
        malicious_count = 0

    result['Status'] = "Malicious" if malicious_count > threshold else "Not Malicious"
    result['Malicious Score'] = malicious_count
    try:
        result['ISP'] = parse_json['data']['attributes']['as_owner']
    except KeyError:
        result['ISP'] = "Not Found!"

    try:
        result['Negara'] = parse_json['data']['attributes']['country']
    except KeyError:
        result['Negara'] = "Not Found!"

    try:
        result['Benua'] = parse_json['data']['attributes']['continent']
    except KeyError:
        result['Benua'] = "Not Found!"

    try:
        whois_data = parse_json['data']['attributes']['whois']
    except KeyError:
        whois_data = "Not Found!"

    result['Alamat'] = extract_whois_info(whois_data, [r"address:\s*(.*)"])
    result['Org'] = extract_whois_info(whois_data, [r"org-name:\s*(.*)", r"org:\s*(.*)", r"organisation:\s*(.*)", r"netname:\s*(.*)"])
    result['Email'] = extract_whois_info(whois_data, [r"e-mail:\s*(.*)", r"abuse-mailbox:\s*(.*)"])
    result['Phone'] = extract_whois_info(whois_data, [r"phone:\s*(.*)"])

    

    results[index] = result
    print_progress_bar(index + 1, total_ips, start_time)

def fetch_url_data(url, index, total_urls, start_time, threshold, results, api_key):
    encoded_url = requests.utils.quote(url, safe='')
    baseline = "https://www.virustotal.com/api/v3/urls"
    payload = { "url": encoded_url }
    headers = {
	    "accept": "application/json",
	    "x-apikey": api_key,
		"content-type": "application/x-www-form-urlencoded"
	}
    response = requests.post(baseline, data=payload, headers=headers)
    parse_json = json.loads(response.text)
    analysis_id=parse_json['data']['links']['self']
    
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response2 = requests.get(analysis_id, headers=headers)
    parse_json2 = json.loads(response2.text)
    item_link = parse_json2['data']['links']['item']
    response3 = requests.get(item_link, headers=headers)
    parse_json3 = json.loads(response3.text)
    result = {'URL': url}
    try:
        result['Kategori'] = parse_json3['data']['attributes']['categories']['Sophos']
    except KeyError:
        result['Kategori'] = "Not Found!"

    try:
        malicious_count = parse_json2['data']['attributes']['stats']['malicious']
    except KeyError:
        malicious_count = 0

    result['Status'] = "Malicious" if malicious_count > threshold else "Not Malicious"
    result['Malicious Score'] = malicious_count
    

    results[index] = result
    print_progress_bar(index + 1, total_urls, start_time)

def fetch_hash_file_data(hash, index, total_hashes, start_time, threshold, results, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    parse_json = json.loads(response.text)

    result = {'Hash': hash}
    try:
        attributes = parse_json['data']['attributes']
    except KeyError:
        attributes = {}
    result['File_Name'] = attributes.get('names', ['Not Found!'])[0]
    malicious_count = attributes.get('last_analysis_stats', {}).get('malicious', 0)
    result['Status'] = "Malicious" if malicious_count > threshold else "Not Malicious"
    result['Malicious_Score'] = malicious_count
    result['Threat Label'] = attributes.get('popular_threat_classification',{}).get('suggested_threat_label', ['Not Found!'])

    endpoints = {
        'Dropped_Files': 'dropped_files',
        'Contacted_Ips': 'contacted_ips',
        'Contacted_Urls': 'contacted_urls',
        'Parents': 'execution_parents'
    }

    for key, endpoint in endpoints.items():
        endpoint_url = f"{url}/{endpoint}?limit=1"
        try:
            endpoint_response = requests.get(endpoint_url, headers=headers)
            endpoint_data = json.loads(endpoint_response.text).get('data', [])
            if endpoint_data and isinstance(endpoint_data, list):
                first_item = endpoint_data[0]
                if key == 'Dropped_Files':
                    result[key] = first_item.get('attributes', {}).get('names', ['Not Found!'])[0]
                elif key == 'Contacted_Ips':
                    result[key] = first_item.get('id', 'Not Found!')
                    result['Contacted_Ips_Score'] = first_item.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                elif key == 'Contacted_Urls':
                    result[key] = first_item.get('attributes', {}).get('url', 'Not Found!')
                    result['Contacted_Urls_Score'] = first_item.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                elif key == 'Parents':
                    result[key] = first_item.get('attributes', {}).get('names', ['Not Found!'])[0]
            else:
                result[key] = "Not Found!"
        except requests.RequestException:
            result[key] = "Not Found!"

    results[index] = result
    print_progress_bar(index + 1, total_hashes, start_time)

def main():
    parser = argparse.ArgumentParser(description="Retrieve information about IP addresses, URLs, or hash files from VirusTotal API and create an Excel file with the data.")
    parser.add_argument("-i", "--ip", type=str, help="Input file containing IP addresses. (-i ip.txt)")
    parser.add_argument("-u", "--urls", type=str, help="Input file containing URLs. (-u url.txt) *url must contain domain only, ex: google.com")
    parser.add_argument("-hf", "--hash_files", type=str, help="Input file containing hash files. (-hf hash.txt)")
    parser.add_argument("-t", "--threshold", type=int, default=3, help="Threshold for considering an item malicious (default: 3, >3 = malicious).")
    parser.add_argument("-o", "--output", type=str, help="Name for the output file (without extension).")
    args = parser.parse_args()

    data_list = []
    data_type = ""
    fetch_data = None

    if args.ip:
        with open(args.ip, "r") as file:
            data_list = [line.strip() for line in file]
        data_type = "IP"
        fetch_data = fetch_ip_data
    elif args.urls:
        with open(args.urls, "r") as file:
            data_list = [line.strip() for line in file]
        data_type = "URL"
        fetch_data = fetch_url_data
    elif args.hash_files:
        with open(args.hash_files, "r") as file:
            data_list = [line.strip() for line in file]
        data_type = "Hash"
        fetch_data = fetch_hash_file_data
    else:
        print("No valid option provided. Use -h for help.")
        return

    total_data = len(data_list)
    start_time = datetime.now()

    print("""
 
░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓████████▓▒░░▒▓██████▓▒░▒▓████████▓▒░       ░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓████████▓▒░▒▓███████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░    ░▒▓██▓▒░░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓████████▓▒░▒▓███████▓▒░░▒▓██████▓▒░ ░▒▓████████▓▒░ ░▒▓█▓▒░          ░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░    ░▒▓██████▓▒░   ░▒▓██▓▒░  ░▒▓██████▓▒░ ░▒▓███████▓▒░  
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░    ░▒▓██▓▒░    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░   ░▒▓█▓▒░      ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ ░▒▓█▓▒░          ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓█▓▒░   ░▒▓████████▓▒░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                                                                                                                                                                                                                                                                                                             
    made by Angger, David, Richie, -h for help
    """)

    api_key = "58db8b60b692dd9e82444c4a243e674fbdffbdefbecc6de3f3bc7b6d754e8b4e"

    results = [None] * total_data
    
    for i, data in enumerate(data_list):
        fetch_data(data, i, total_data, start_time, args.threshold, results, api_key)

    data_frame = pd.DataFrame(results)
    output_file = f"{args.output}.xlsx" if args.output else "output.xlsx"

    writer = pd.ExcelWriter(output_file, engine='openpyxl')
    data_frame.to_excel(writer, index=False, sheet_name=f'Data_{data_type}')
    
    if data_type == "IP":
        country_counts = data_frame['Negara'].value_counts()
        country_df = pd.DataFrame({'Negara': country_counts.index, 'Jumlah_IP': country_counts.values})

        continent_counts = data_frame['Benua'].value_counts()
        continent_df = pd.DataFrame({'Benua': continent_counts.index, 'Jumlah_IP': continent_counts.values})

        status_counts = data_frame['Status'].value_counts()
        status_df = pd.DataFrame({'Status': status_counts.index, 'Jumlah_IP': status_counts.values})

        isp_counts = data_frame['ISP'].value_counts()
        isp_df = pd.DataFrame({'ISP': isp_counts.index, 'Jumlah_IP': isp_counts.values})

        status_df.to_excel(writer, index=False, sheet_name='Grafik_Status')
        continent_df.to_excel(writer, index=False, sheet_name='Grafik_Benua')
        country_df.to_excel(writer, index=False, sheet_name='Grafik_Negara')
        isp_df.to_excel(writer, index=False, sheet_name='Grafik_ISP')

        add_chart_to_sheet(writer.sheets['Grafik_Status'], 'Status', 'Jumlah_IP', 'K2', 'Jumlah IP Berdasarkan Status')
        add_chart_to_sheet(writer.sheets['Grafik_Benua'], 'Benua', 'Jumlah_IP', 'K2', 'Jumlah IP Berdasarkan Benua')
        add_chart_to_sheet(writer.sheets['Grafik_Negara'], 'Negara', 'Jumlah_IP', 'K2', 'Jumlah IP Berdasarkan Negara')
        add_chart_to_sheet(writer.sheets['Grafik_ISP'], 'ISP', 'Jumlah_IP', 'K2', 'Jumlah IP Berdasarkan ISP')

        glosarium_df = pd.DataFrame({
        'Item': ['IP', 'Status', 'Malicious Score', 'ISP', 'Negara', 'Benua', 'Alamat', 'Org', 'Email', 'Phone'],
        'Keterangan': ['Alamat IP yang ingin Anda analisis.',
                    'Status reputasi IP. Berisikan Malicious atau Not Malicious berdasarkan batasan yang telah diberikan.',
                    'Skor yang menunjukkan tingkat bahaya IP. Semakin tinggi skornya, semakin berbahaya IP tersebut.',
                    'Penyedia layanan internet (ISP) yang digunakan IP.',
                    'Negara tempat IP berada.',
                    'Benua tempat IP berada.',
                    'Alamat fisik yang terkait dengan IP (jika tersedia).',
                    'Organisasi yang terkait dengan IP (jika tersedia).',
                    'Alamat email yang terkait dengan IP (jika tersedia).',
                    'Nomor telepon yang terkait dengan IP (jika tersedia).']
        })
        glosarium_df.to_excel(writer, index=False, sheet_name='Executive Summary')

        worksheet = writer.sheets['Executive Summary']
        worksheet['A13'] = "Ringkasan Eksekutif:"
        worksheet['A14'] = "Dari data IP yang diberikan, dapat dilihat bahwa negara {} mendominasi dengan jumlah IP tertinggi dengan jumlah {} ip, kemudian didapati juga benua {} sebagai benua dengan serangan terbanyak dengan jumlah {} ip. Tidak kalah penting juga ISP sebagai tolak ukur analisa dimana didapatkan ISP {} sebagai ISP dengan serangan terbanyak sejumlah {} ip. Dari hasil analisa dapat disimpulkan kalau analisa didominasi oleh {} dengan jumlah {} ip.".format(country_counts.index[0], country_counts.values[0], continent_counts.index[0], continent_counts.values[0], isp_counts.index[0], isp_counts.values[0],status_counts.index[0], status_counts.values[0])

        worksheet['A15'] = "Mitigasi:"
        worksheet['A16'] = "- Pantau aktivitas IP dari negara {} dengan cermat untuk mengurangi risiko. Apabila negara tergolong berbahaya, dapat lakukan blocking segala aktivitas IP yang berasal dari negara tersebut".format(country_counts.index[0])
        worksheet['A17'] = "- Lakukan penelitian lebih lanjut terkait IP dari benua {} untuk menentukan langkah yang akan diambil.".format(continent_counts.index[0])
        worksheet['A17'] = "- Analisa lebih mendalam terkait ISP {}, dan identifikasikan untuk melakukan pencegahan insider threat.".format(isp_counts.index[0])
        worksheet['A18'] = "- Tindak lanjuti IP dengan status malicious dengan langkah-langkah mitigasi yang sesuai."


    elif data_type == "URL":
        category_counts = data_frame['Kategori'].value_counts()
        category_df = pd.DataFrame({'Kategori': category_counts.index, 'Jumlah_URL': category_counts.values})

        status_counts = data_frame['Status'].value_counts()
        status_df = pd.DataFrame({'Status': status_counts.index, 'Jumlah_URL': status_counts.values})

        category_df.to_excel(writer, index=False, sheet_name='Grafik_Kategori')
        status_df.to_excel(writer, index=False, sheet_name='Grafik_Status')

        add_chart_to_sheet(writer.sheets['Grafik_Kategori'], 'Kategori', 'Jumlah_URL', 'K2', 'Jumlah URL Berdasarkan Kategori')
        add_chart_to_sheet(writer.sheets['Grafik_Status'], 'Status', 'Jumlah_URL', 'K2', 'Jumlah URL Berdasarkan Status')

        url_glosarium_df = pd.DataFrame({
            'Item': ['URL', 'Kategori', 'Status', 'Malicious Score'],
            'Keterangan': ['URL yang ingin Anda analisis.',
                        'Kategori yang diberikan untuk mengidentifikasi url yang sedang dianalisa',
                        'Status reputasi URL. Berisikan Malicious atau Not Malicious berdasarkan batasan yang telah diberikan.',
                        'Skor yang menunjukkan tingkat bahaya URL. Semakin tinggi skornya, semakin berbahaya URL tersebut.']
        })
        url_glosarium_df.to_excel(writer, index=False, sheet_name='Executive Summary')

        worksheet = writer.sheets['Executive Summary']
        worksheet['A13'] = "Ringkasan Eksekutif:"
        worksheet['A14'] = "Dari data URL yang diberikan, dapat dilihat url didominasi dengan status {} sebanyak {} url, kemudian kategori yang paling banyak merupakan kategori {} sebanyak {} url.".format(status_counts.index[0], status_counts.values[0], category_counts.index[0], category_counts.values[0])

        worksheet['A15'] = "Mitigasi:"
        worksheet['A16'] = "- Pelajari mengenai kategori threat {}, sehingga dapat mengetahui langkah mitigasi yang sesuai".format(category_counts.index[0])
        worksheet['A17'] = "- Hindari mengakses URL yang tergolong dalam malicious, dan lakukan analisa lebih mendalam"

    elif data_type == "Hash":
        category_counts = data_frame['Threat Label'].value_counts()
        category_df = pd.DataFrame({'Threat Label': category_counts.index, 'Jumlah Hash': category_counts.values})

        status_counts = data_frame['Status'].value_counts()
        status_df = pd.DataFrame({'Status': status_counts.index, 'Jumlah Hash': status_counts.values})
    
        category_df.to_excel(writer, index=False, sheet_name='Grafik Threat Label')
        status_df.to_excel(writer, index=False, sheet_name='Grafik Status')

        add_chart_to_sheet(writer.sheets['Grafik Threat Label'], 'Threat Label', 'Jumlah Hash', 'K2', 'Jumlah URL Berdasarkan Kategori')
        add_chart_to_sheet(writer.sheets['Grafik Status'], 'Status', 'Jumlah Hash', 'K2', 'Jumlah URL Berdasarkan Status')

        worksheet = writer.sheets['Grafik Threat Label']
        worksheet = writer.sheets['Grafik Status']
        

        hash_glosarium_df = pd.DataFrame({
        'Item': ['Hash', 'File Name', 'Status', 'Malicious Score', 'Threat Label', 'Dropped Files', 'Contacted IP', 'Contacted IP Score', 'Contacted URL', 'Contacted URL Score','Parents'],
        'Keterangan': ['Hash yang ingin Anda analisis.',
                    'Nama file terkait dengan hash.',
                    'Status reputasi Hash. Berisikan Malicious atau Not Malicious berdasarkan batasan yang telah diberikan.',
                    'Skor yang menunjukkan tingkat bahaya hash. Semakin tinggi skornya, semakin berbahaya file tersebut.',
                    'Label atau klasifikasi yang diberikan untuk mengidentifikasi hash file yang sedang dianalisa',
                    'File yang dibuat atau dihasilkan oleh file yang sedang dianalisa.',
                    'Alamat IP yang dihubungi oleh file. Biasanya memiliki keterkaitan pada sebuah cyber attack chain',
                    'Skor yang menunjukan tingkat bahaya pada IP yang dihubungi oleh file',
                    'URL yang dihubungi oleh file. Biasanya memiliki keterkaitan pada sebuah cyber attack chain',
                    'Skor yang menunjukan tingkat bahaya pada URL yang dihubungi oleh file',
                    'File yang memicu eksekusi file terkait. Dapat menjadi awal mula dari cyber attack chain']
        })
        hash_glosarium_df.to_excel(writer, index=False, sheet_name='Executive Summary')

        worksheet = writer.sheets['Executive Summary']
        worksheet['A15'] = "Ringkasan Eksekutif:"
        worksheet['A16'] = "Dari data hash yang diberikan, dapat dilihat bahwa threat label {} mendominasi dengan jumlah hash tertinggi yaitu {} hash, kemudian dari hasil analisa dapat disimpulkan kalau hash didominasi oleh {} hash dengan jumlah {} hash.".format(category_counts.index[0], category_counts.values[0], status_counts.index[0], status_counts.values[0])

        worksheet['A17'] = "Mitigasi:"
        worksheet['A18'] = "- Lakukan penelitian lebih lanjut terkait threat label {} untuk menentukan langkah penanganan yang akan diambil.".format(category_counts.index[0])
        worksheet['A20'] = "- Analisa lebih mendalam menggunakan data yang sudah ada, cari korelasi dan cyber attack chain menggunakan parameter seperti parent, dropped files, dan juga contacted url ataupun ip."
        worksheet['A21'] = "- Tindak lanjuti hash dengan status malicious dengan langkah-langkah mitigasi yang sesuai."

    writer._save()
    print("\nSuccess!")


def add_chart_to_sheet(sheet, category_col, value_col, cell_position, title):
    chart = BarChart()
    chart.title = title
    data = Reference(sheet, min_col=2, min_row=1, max_row=sheet.max_row)
    categories = Reference(sheet, min_col=1, min_row=2, max_row=sheet.max_row)
    chart.add_data(data, titles_from_data=True)
    chart.set_categories(categories)
    sheet.add_chart(chart, cell_position)

if __name__ == "__main__":
    main()

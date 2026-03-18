import requests
import json
import pandas as pd
import matplotlib.pyplot as plt
import vt
# -----------------------------
# API КЛЮЧИ
# -----------------------------

VT_API_KEY = "d6e638b36faa82299c8cf74c5ff71b56ac0eb10f4deafe31714fe42c7d93ff08"
VULNERS_API_KEY = "SLJKC7O8WR5IXY0329XBEXH85RK6934OUW345BQ6VNNAFW0RRHZDJZDNC6O8NZ5J"


FILE_HASH = input("Введите SHA-256 хэш файла: ").strip()

# CVE для проверки через Vulners
CVE_QUERY = "CVE-2023-23397"


# -----------------------------
# 1. VIRUSTOTAL API
# -----------------------------

def get_virustotal_data():

    url = f"https://www.virustotal.com/api/v3/files/{FILE_HASH}"

    headers = {
        "x-apikey": VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print("Ошибка VirusTotal:", response.status_code)
        return None

    data = response.json()

    stats = data["data"]["attributes"]["last_analysis_stats"]

    vt_stats = {
        "malicious": stats["malicious"],
        "suspicious": stats["suspicious"],
        "harmless": stats["harmless"],
        "undetected": stats["undetected"]
    }

    print("VirusTotal данные получены")

    return vt_stats


# -----------------------------
# 2. VULNERS API
# -----------------------------

def get_vulners_data():

    url = "https://vulners.com/api/v3/search/lucene/"

    headers = {
        "X-Api-Key": VULNERS_API_KEY,
        "Content-Type": "application/json"
    }

    payload = {
        "query": CVE_QUERY,
        "size": 5
    }

    response = requests.post(url, headers=headers, json=payload)

    if response.status_code != 200:
        print("Ошибка Vulners:", response.status_code)
        return None

    data = response.json()

    vulns = []

    for item in data["data"]["search"]:
        vulns.append({
            "id": item.get("id"),
            "title": item.get("title"),
            "cvss": item.get("cvss", {}).get("score", 0)
        })

    print("Vulners данные получены")

    return vulns


# -----------------------------
# 3. Загрузка логов
# -----------------------------

def load_logs():

    logs = [
        {"ip": "192.168.1.5", "requests": 10},
        {"ip": "192.168.1.10", "requests": 250},
        {"ip": "10.0.0.3", "requests": 320},
        {"ip": "172.16.0.5", "requests": 8},
        {"ip": "10.0.0.9", "requests": 140}
    ]

    df = pd.DataFrame(logs)

    print("Логи загружены")

    return df


# -----------------------------
# 4. Анализ логов
# -----------------------------

def analyze_logs(df):

    suspicious = df[df["requests"] > 50]

    print("\nПодозрительные IP:")

    print(suspicious)

    return suspicious


# -----------------------------
# 5. Имитация реагирования
# -----------------------------

def respond_to_threats(suspicious_ips):

    print("\nРеагирование:")

    for _, row in suspicious_ips.iterrows():
        print(f"⚠ Блокировка IP (имитация): {row['ip']}")


# -----------------------------
# 6. Формирование отчета
# -----------------------------

def save_report(vt_stats, vulners_data, suspicious_ips):

    report = {
        "virustotal_stats": vt_stats,
        "vulnerabilities": vulners_data,
        "suspicious_ips": suspicious_ips.to_dict(orient="records")
    }

    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print("\nОтчёт сохранён: report.json")



# -----------------------------
# 7. Создание графика
# -----------------------------

def create_graph(vt_stats):

    labels = list(vt_stats.keys())
    values = list(vt_stats.values())

    plt.figure()

    plt.bar(labels, values)

    plt.title("VirusTotal Scan Results")
    plt.xlabel("Категория")
    plt.ylabel("Количество")

    plt.savefig("vt_stats.png")

    print("График сохранён: vt_stats.png")


# -----------------------------
# MAIN
# -----------------------------

def main():

    vt_stats = get_virustotal_data()

    vulners_data = get_vulners_data()

    logs_df = load_logs()

    suspicious_ips = analyze_logs(logs_df)

    respond_to_threats(suspicious_ips)

    save_report(vt_stats, vulners_data, suspicious_ips)

    create_graph(vt_stats)


if __name__ == "__main__":
    main()
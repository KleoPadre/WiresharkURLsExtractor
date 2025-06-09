#!/usr/bin/env python3
"""
Скрипт для извлечения HTTPS-доменов из всех PCAPNG файлов в папке 'capture'.
Результат сохраняется в папку 'results' с датой и временем в названии.
"""

import pyshark
import re
import os
from urllib.parse import urlparse
from datetime import datetime

def is_ip_address(hostname):
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    return bool(re.match(ipv4_pattern, hostname)) or bool(re.match(ipv6_pattern, hostname))

def extract_domain_from_url(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if hostname and not is_ip_address(hostname):
            return hostname.lower()
    except:
        return None
    return None

def process_pcapng(file_path):
    domains = set()
    try:
        # Первый проход - подсчитываем общее количество пакетов с TLS SNI
        print("    Подсчет TLS пакетов...", end="", flush=True)
        cap = pyshark.FileCapture(file_path, display_filter='tls.handshake.extensions_server_name')
        tls_packets = sum(1 for _ in cap)
        cap.close()
        
        # Подсчитываем HTTP пакеты с Host заголовком
        print(" и HTTP пакетов...", end="", flush=True)
        cap = pyshark.FileCapture(file_path, display_filter='http.host')
        http_packets = sum(1 for _ in cap)
        cap.close()
        
        total_packets = tls_packets + http_packets
        print(f" найдено {tls_packets} TLS + {http_packets} HTTP = {total_packets} пакетов")
        
        if total_packets == 0:
            print("    Нет пакетов с доменами для обработки")
            return domains
        
        processed = 0
        
        # Обрабатываем TLS пакеты
        if tls_packets > 0:
            cap = pyshark.FileCapture(file_path, display_filter='tls.handshake.extensions_server_name')
            for pkt in cap:
                try:
                    if hasattr(pkt.tls, 'handshake_extensions_server_name'):
                        domain = pkt.tls.handshake_extensions_server_name
                        cleaned = extract_domain_from_url("https://" + domain)
                        if cleaned:
                            domains.add(cleaned)
                except AttributeError:
                    continue
                
                processed += 1
                if processed % max(1, total_packets // 20) == 0:
                    progress = (processed / total_packets) * 100
                    print(f"\r    Обработано: {processed}/{total_packets} пакетов ({progress:.1f}%)", end="", flush=True)
            cap.close()
        
        # Обрабатываем HTTP пакеты
        if http_packets > 0:
            cap = pyshark.FileCapture(file_path, display_filter='http.host')
            for pkt in cap:
                try:
                    if hasattr(pkt.http, 'host'):
                        domain = pkt.http.host
                        cleaned = extract_domain_from_url("http://" + domain)
                        if cleaned:
                            domains.add(cleaned)
                except AttributeError:
                    continue
                
                processed += 1
                if processed % max(1, total_packets // 20) == 0:
                    progress = (processed / total_packets) * 100
                    print(f"\r    Обработано: {processed}/{total_packets} пакетов ({progress:.1f}%)", end="", flush=True)
            cap.close()
        
        # Финальный прогресс
        print(f"\r    Обработано: {processed}/{total_packets} пакетов (100.0%)")
        
    except Exception as e:
        print(f"\n    Ошибка при обработке {file_path}: {e}")
    return domains

def main():
    capture_dir = "capture"
    results_dir = "results"
    os.makedirs(results_dir, exist_ok=True)

    # Получаем список всех .pcapng файлов
    pcapng_files = [f for f in os.listdir(capture_dir) if f.endswith(".pcapng")]
    total_files = len(pcapng_files)
    
    if total_files == 0:
        print("Не найдено ни одного .pcapng файла в папке 'capture'")
        return
    
    print(f"Найдено {total_files} файлов для обработки")
    print("-" * 50)

    all_domains = set()
    for i, filename in enumerate(pcapng_files, 1):
        file_path = os.path.join(capture_dir, filename)
        print(f"[{i}/{total_files}] Обработка: {filename}")
        domains = process_pcapng(file_path)
        
        # Показываем новые домены из этого файла
        new_domains = domains - all_domains
        all_domains.update(domains)
        
        print(f"    Найдено доменов в файле: {len(domains)}")
        print(f"    Новых доменов: {len(new_domains)}")
        print(f"    Всего уникальных доменов: {len(all_domains)}")
        print(f"    Прогресс файлов: {i/total_files*100:.1f}%")
        
        # Показываем несколько примеров новых доменов
        if new_domains:
            sample_domains = list(new_domains)[:5]
            print(f"    Примеры новых: {', '.join(sample_domains)}")
        
        print("-" * 50)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    result_path = os.path.join(results_dir, f"domains_{timestamp}.txt")

    with open(result_path, "w") as f:
        for domain in sorted(all_domains):
            f.write(domain + "\n")

    print("✓ ЗАВЕРШЕНО!")
    print(f"Обработано файлов: {total_files}")
    print(f"Найдено уникальных доменов: {len(all_domains)}")
    print(f"Результат сохранён в: {result_path}")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
"""
Диагностический скрипт для анализа PCAPNG файла
Показывает все найденные домены и детали пакетов
"""

import pyshark
import sys
import re
from urllib.parse import urlparse

def is_ip_address(hostname):
    """Проверяет, является ли строка IP-адресом"""
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    return bool(re.match(ipv4_pattern, hostname)) or bool(re.match(ipv6_pattern, hostname))

def analyze_pcap_detailed(pcap_file_path, search_domains=None):
    """
    Детальный анализ PCAPNG файла с поиском конкретных доменов
    
    Args:
        pcap_file_path (str): Путь к PCAPNG файлу
        search_domains (list): Список доменов для поиска
    """
    if search_domains is None:
        search_domains = ['googlevideo.com', 'yt3.ggpht.com', 'ytimg.com', 'youtube.com']
    
    found_domains = set()
    all_http_hosts = set()
    all_tls_sni = set()
    all_dns_queries = set()
    matching_packets = []
    
    try:
        print(f"=== Анализ файла: {pcap_file_path} ===")
        print(f"Ищем домены содержащие: {search_domains}")
        print("=" * 60)
        
        cap = pyshark.FileCapture(pcap_file_path)
        
        packet_count = 0
        for packet in cap:
            packet_count += 1
            
            if packet_count % 1000 == 0:
                print(f"Обработано пакетов: {packet_count}")
            
            packet_info = {
                'number': packet_count,
                'protocols': [],
                'domains': []
            }
            
            try:
                # Анализ HTTP трафика
                if hasattr(packet, 'http'):
                    packet_info['protocols'].append('HTTP')
                    http_layer = packet.http
                    
                    # Host заголовок
                    if hasattr(http_layer, 'host'):
                        host = http_layer.host
                        all_http_hosts.add(host)
                        packet_info['domains'].append(f"HTTP Host: {host}")
                        
                        # Проверяем на совпадение с искомыми доменами
                        for search_domain in search_domains:
                            if search_domain in host:
                                found_domains.add(host)
                                matching_packets.append({
                                    'packet': packet_count,
                                    'type': 'HTTP Host',
                                    'domain': host,
                                    'protocol': 'HTTP'
                                })
                    
                    # Referer заголовок
                    if hasattr(http_layer, 'referer'):
                        referer = http_layer.referer
                        try:
                            parsed = urlparse(referer)
                            if parsed.netloc:
                                all_http_hosts.add(parsed.netloc)
                                packet_info['domains'].append(f"HTTP Referer: {parsed.netloc}")
                                
                                for search_domain in search_domains:
                                    if search_domain in parsed.netloc:
                                        found_domains.add(parsed.netloc)
                                        matching_packets.append({
                                            'packet': packet_count,
                                            'type': 'HTTP Referer',
                                            'domain': parsed.netloc,
                                            'protocol': 'HTTP'
                                        })
                        except:
                            pass
                
                # Анализ TLS/SSL трафика
                if hasattr(packet, 'tls'):
                    packet_info['protocols'].append('TLS')
                    tls_layer = packet.tls
                    
                    # SNI (Server Name Indication)
                    if hasattr(tls_layer, 'handshake_extensions_server_name'):
                        sni = tls_layer.handshake_extensions_server_name
                        if sni and not is_ip_address(sni):
                            all_tls_sni.add(sni)
                            packet_info['domains'].append(f"TLS SNI: {sni}")
                            
                            for search_domain in search_domains:
                                if search_domain in sni:
                                    found_domains.add(sni)
                                    matching_packets.append({
                                        'packet': packet_count,
                                        'type': 'TLS SNI',
                                        'domain': sni,
                                        'protocol': 'TLS'
                                    })
                    
                    # Дополнительные поля TLS
                    tls_fields = [
                        'handshake_extensions_server_name_list_len',
                        'handshake_extensions_server_name_len',
                        'handshake_extensions_server_name_type'
                    ]
                    
                    for field in tls_fields:
                        if hasattr(tls_layer, field):
                            value = getattr(tls_layer, field)
                            if isinstance(value, str) and '.' in value and not is_ip_address(value):
                                all_tls_sni.add(value)
                                packet_info['domains'].append(f"TLS {field}: {value}")
                
                # Анализ DNS запросов
                if hasattr(packet, 'dns'):
                    packet_info['protocols'].append('DNS')
                    dns_layer = packet.dns
                    
                    # DNS запросы
                    if hasattr(dns_layer, 'qry_name'):
                        dns_name = dns_layer.qry_name
                        if dns_name and not dns_name.endswith('.') and not is_ip_address(dns_name):
                            all_dns_queries.add(dns_name)
                            packet_info['domains'].append(f"DNS Query: {dns_name}")
                            
                            for search_domain in search_domains:
                                if search_domain in dns_name:
                                    found_domains.add(dns_name)
                                    matching_packets.append({
                                        'packet': packet_count,
                                        'type': 'DNS Query',
                                        'domain': dns_name,
                                        'protocol': 'DNS'
                                    })
                
                # Если найдены домены в этом пакете, выводим детали
                if packet_info['domains']:
                    for domain_info in packet_info['domains']:
                        for search_domain in search_domains:
                            if search_domain in domain_info:
                                print(f"НАЙДЕН! Пакет #{packet_count}: {domain_info}")
                
            except Exception as e:
                continue
        
        cap.close()
        
        print(f"\n=== РЕЗУЛЬТАТЫ АНАЛИЗА ===")
        print(f"Всего обработано пакетов: {packet_count}")
        print(f"Найдено HTTP хостов: {len(all_http_hosts)}")
        print(f"Найдено TLS SNI: {len(all_tls_sni)}")
        print(f"Найдено DNS запросов: {len(all_dns_queries)}")
        
        print(f"\n=== СОВПАДЕНИЯ С ИСКОМЫМИ ДОМЕНАМИ ===")
        if matching_packets:
            for match in matching_packets:
                print(f"Пакет #{match['packet']}: {match['type']} -> {match['domain']} ({match['protocol']})")
        else:
            print("Совпадений не найдено!")
        
        print(f"\n=== ВСЕ НАЙДЕННЫЕ ДОМЕНЫ (первые 50) ===")
        all_domains = sorted(list(all_http_hosts | all_tls_sni | all_dns_queries))
        for i, domain in enumerate(all_domains[:50]):
            print(f"{i+1}. {domain}")
        
        if len(all_domains) > 50:
            print(f"... и еще {len(all_domains) - 50} доменов")
        
        print(f"\n=== ПОИСК ПО ПОДСТРОКАМ ===")
        for search_domain in search_domains:
            matches = [d for d in all_domains if search_domain in d.lower()]
            if matches:
                print(f"Домены содержащие '{search_domain}':")
                for match in matches:
                    print(f"  - {match}")
            else:
                print(f"Домены содержащие '{search_domain}': НЕ НАЙДЕНО")
        
        return True
        
    except Exception as e:
        print(f"Ошибка при анализе файла: {e}")
        return False

def main():
    """Основная функция"""
    if len(sys.argv) < 2:
        print("Использование: python diagnostic.py <путь_к_pcapng_файлу> [домен1] [домен2] ...")
        print("Пример: python diagnostic.py capture.pcapng googlevideo.com ytimg.com")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    search_domains = sys.argv[2:] if len(sys.argv) > 2 else None
    
    # Проверяем существование файла
    try:
        with open(pcap_file, 'rb') as f:
            pass
    except FileNotFoundError:
        print(f"Файл не найден: {pcap_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при открытии файла: {e}")
        sys.exit(1)
    
    # Анализируем файл
    success = analyze_pcap_detailed(pcap_file, search_domains)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()

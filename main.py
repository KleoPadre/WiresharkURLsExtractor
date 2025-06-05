#!/usr/bin/env python3
"""
Скрипт для извлечения HTTPS доменов из PCAPNG файла
Требует установки: pip install pyshark
"""

import pyshark
import re
import sys
import os
from urllib.parse import urlparse
from collections import OrderedDict

def is_ip_address(hostname):
    """
    Проверяет, является ли строка IP-адресом
    
    Args:
        hostname (str): Строка для проверки
    
    Returns:
        bool: True если это IP-адрес
    """
    # Простая проверка на IPv4
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    # Простая проверка на IPv6
    ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    return bool(re.match(ipv4_pattern, hostname)) or bool(re.match(ipv6_pattern, hostname))

def extract_domain_from_url(url):
    """
    Извлекает только доменное имя из URL
    
    Args:
        url (str): Полный URL
    
    Returns:
        str or None: Доменное имя без пути, или None если не подходит
    """
    try:
        parsed = urlparse(url)
        
        # Проверяем, что это HTTPS
        if parsed.scheme != 'https':
            return None
        
        hostname = parsed.netloc
        
        # Убираем порт если есть
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Проверяем, что это не IP-адрес
        if is_ip_address(hostname):
            return None
        
        # Проверяем, что это не локальный адрес
        if any(hostname.startswith(local) for local in 
              ['127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', 
               '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', 
               '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', 
               '172.29.', '172.30.', '172.31.', 'localhost']):
            return None
        
        # Проверяем, что домен содержит точку (базовая валидация)
        if '.' not in hostname:
            return None
        
        return hostname
        
    except Exception:
        return None

def extract_domains_from_pcap(pcap_file_path, output_file_path):
    """
    Извлекает HTTPS домены из PCAPNG файла и сохраняет их в текстовый файл
    
    Args:
        pcap_file_path (str): Путь к PCAPNG файлу
        output_file_path (str): Путь к выходному текстовому файлу
    """
    domains = set()  # Используем set для избежания дубликатов
    
    try:
        print(f"Открываем файл: {pcap_file_path}")
        cap = pyshark.FileCapture(pcap_file_path)
        
        packet_count = 0
        for packet in cap:
            packet_count += 1
            if packet_count % 1000 == 0:
                print(f"Обработано пакетов: {packet_count}")
            
            try:
                # Поиск HTTP трафика (но сохраняем только HTTPS)
                if hasattr(packet, 'http'):
                    http_layer = packet.http
                    
                    # Извлекаем Host и URI для построения полного URL
                    host = getattr(http_layer, 'host', None)
                    uri = getattr(http_layer, 'request_uri', None)
                    
                    if host:
                        # Проверяем, что это HTTPS порт или принудительно делаем HTTPS
                        protocol = 'https'
                        if hasattr(packet, 'tcp') and packet.tcp.dstport == '443':
                            protocol = 'https'
                        elif hasattr(packet, 'tcp') and packet.tcp.dstport == '80':
                            # Пропускаем HTTP трафик
                            continue
                        
                        full_url = f"{protocol}://{host}"
                        domain = extract_domain_from_url(full_url)
                        if domain:
                            domains.add(domain)
                    
                    # Также ищем Referer заголовки
                    referer = getattr(http_layer, 'referer', None)
                    if referer:
                        domain = extract_domain_from_url(referer)
                        if domain:
                            domains.add(domain)
                
                # Поиск HTTPS/TLS трафика (SNI - Server Name Indication)
                if hasattr(packet, 'tls'):
                    try:
                        tls_layer = packet.tls
                        if hasattr(tls_layer, 'handshake_extensions_server_name'):
                            server_name = tls_layer.handshake_extensions_server_name
                            if server_name and not is_ip_address(server_name):
                                # Убираем порт если есть
                                if ':' in server_name:
                                    server_name = server_name.split(':')[0]
                                
                                # Проверяем, что это не локальный адрес
                                if not any(server_name.startswith(local) for local in 
                                          ['127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', 
                                           '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', 
                                           '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', 
                                           '172.29.', '172.30.', '172.31.', 'localhost']):
                                    if '.' in server_name:  # Базовая валидация домена
                                        domains.add(server_name)
                    except:
                        pass
                
                # Поиск DNS запросов (но сохраняем только как HTTPS)
                if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                    domain_name = packet.dns.qry_name
                    if domain_name and not domain_name.endswith('.') and not is_ip_address(domain_name):
                        # Проверяем, что это не локальный адрес
                        if not any(domain_name.startswith(local) for local in 
                                  ['127.', '192.168.', '10.', '172.16.', '172.17.', '172.18.', 
                                   '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', 
                                   '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', 
                                   '172.29.', '172.30.', '172.31.', 'localhost']):
                            if '.' in domain_name:  # Базовая валидация домена
                                domains.add(domain_name)
                
            except Exception as e:
                # Пропускаем пакеты с ошибками
                continue
        
        cap.close()
        print(f"Всего обработано пакетов: {packet_count}")
        
    except Exception as e:
        print(f"Ошибка при чтении PCAP файла: {e}")
        return False
    
    # Сортируем домены
    filtered_domains = sorted(list(domains))
    
    # Создаем папку results если её нет
    results_dir = 'results'
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
        print(f"Создана папка: {results_dir}")
    
    # Сохраняем в файл
    try:
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"HTTPS домены из файла: {pcap_file_path}\n")
            f.write(f"Всего найдено уникальных доменов: {len(filtered_domains)}\n")
            f.write("=" * 50 + "\n\n")
            
            for domain in filtered_domains:
                f.write(domain + "\n")
        
        print(f"Найдено уникальных HTTPS доменов: {len(filtered_domains)}")
        print(f"Результаты сохранены в файл: {output_file_path}")
        return True
        
    except Exception as e:
        print(f"Ошибка при сохранении файла: {e}")
        return False

def generate_output_filename(input_filename):
    """
    Генерирует имя выходного файла на основе входного
    
    Args:
        input_filename (str): Имя входного файла
    
    Returns:
        str: Путь к выходному файлу
    """
    # Убираем расширение из имени файла
    base_name = os.path.splitext(os.path.basename(input_filename))[0]
    
    # Создаем имя выходного файла
    output_filename = f"urls-{base_name}.txt"
    
    # Возвращаем полный путь в папке results
    return os.path.join('results', output_filename)

def main():
    """Основная функция"""
    if len(sys.argv) != 2:
        print("Использование: python script.py <путь_к_pcapng_файлу>")
        print("Пример: python script.py capture.pcapng")
        print("Выходной файл будет создан автоматически в папке results/")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    
    # Проверяем существование входного файла
    try:
        with open(pcap_file, 'rb') as f:
            pass
    except FileNotFoundError:
        print(f"Файл не найден: {pcap_file}")
        sys.exit(1)
    except Exception as e:
        print(f"Ошибка при открытии файла: {e}")
        sys.exit(1)
    
    # Генерируем имя выходного файла
    output_file = generate_output_filename(pcap_file)
    
    print(f"Входной файл: {pcap_file}")
    print(f"Выходной файл: {output_file}")
    
    # Извлекаем домены
    success = extract_domains_from_pcap(pcap_file, output_file)
    
    if success:
        print("Обработка завершена успешно!")
    else:
        print("Произошла ошибка при обработке файла.")
        sys.exit(1)

if __name__ == "__main__":
    main()
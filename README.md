# PCAPNG HTTPS Domain Extractor

Инструмент для извлечения HTTPS доменов из файлов захвата сетевого трафика (PCAPNG) с использованием Python и Wireshark.

## 📋 Описание

Этот скрипт анализирует файлы PCAPNG (созданные Wireshark или другими сетевыми анализаторами) и извлекает из них только чистые доменные имена HTTPS-сайтов. Скрипт фильтрует результаты, убирая HTTP-адреса, IP-адреса, локальные адреса и пути после доменного имени.

### Что делает скрипт:

- ✅ Извлекает только HTTPS домены (HTTP игнорируются)
- ✅ Убирает пути после доменного имени (`example.com/path` → `example.com`)
- ✅ Исключает IP-адреса (`192.168.1.1`, `2001:db8::1`)
- ✅ Фильтрует локальные адреса (`localhost`, `192.168.x.x`, `10.x.x.x`)
- ✅ Удаляет дубликаты и сортирует результаты
- ✅ Автоматически именует выходные файлы
- ✅ Сохраняет результаты в отдельную папку

## 🔧 Требования

### Системные требования:

- Python 3.6+
- Wireshark (включает tshark)

### Python библиотеки:

- `pyshark` - для анализа PCAPNG файлов

## 📦 Установка

### 1. Установка Wireshark

**Windows:**

1. Скачайте Wireshark с [официального сайта](https://www.wireshark.org/download.html)
2. Установите `.exe` файл
3. Убедитесь, что выбрана опция установки `tshark`

**Linux (Ubuntu/Debian):**

```bash
sudo apt update
sudo apt install wireshark tshark
```

**Linux (CentOS/RHEL):**

```bash
sudo yum install wireshark wireshark-cli
# или для новых версий:
sudo dnf install wireshark wireshark-cli
```

**macOS:**

```bash
# Через Homebrew
brew install wireshark
```

### 2. Проверка установки tshark

```bash
tshark --version
```

### 3. Установка Python зависимостей

**Глобальная установка:**

```bash
pip install pyshark
```

**Или создание виртуального окружения (рекомендуется):**

```bash
# Создание виртуального окружения
python -m venv venv

# Активация виртуального окружения
# Linux/macOS:
source venv/bin/activate
# Windows:
venv\Scripts\activate

# Установка зависимостей
pip install pyshark
```

## 📥 Получение `.pcapng` файла на роутере Keenetic

Чтобы получить `.pcapng` файл с роутера Keenetic для анализа в Wireshark:

1. Перейдите в веб-интерфейс Keenetic
2. Откройте раздел **Управление → Диагностика → Захват сетевых пакетов**

<img width="1375" alt="image" src="https://github.com/user-attachments/assets/47d8722b-604d-422c-a10e-8fbd70d47482" />

3. Создайте правило, нажав кнопку **Добавить правило захвата**, выберите подключение, через которое хотите собрать адреса и выберете, куда сохранять файл
   4.Лучше создать правила захвата для несокльких интерфейсов (все WiFi, подключение провайдера, VLAN)

![image](https://github.com/user-attachments/assets/f16a93ec-3d1b-498d-af79-857c8c2ac82d)

   
5. Нужно выбрать флешку как место сохрарения в поле **Место хранения**, так как файл может быть намного больше 100мб
6. Нажмите **Сохранить**

<img width="497" alt="image" src="https://github.com/user-attachments/assets/64ebeda6-4d9b-4e5c-8f2c-395e5439696e" />

7. Нажмите кнопку **Запустить**
8. Открывайте сайты, с которых хотите собрать адреса (на компьютере, телевизове, телефоне)
9. Через некоторое время нажмите **Остановить**
10. Скачайте полученные `.pcapng` файл на компьютер

Теперь вы можете использовать эти файл с данным проектом для анализа URL и доменов.

## 🚀 Использование

### Основной скрипт

```bash
python main.py
```

## 📁 Структура проекта

```
pcapng-extractor/
├── main.py                 # Основной скрипт для извлечения доменов
├── DevTools.py             # Cкрипт для извлечения доменов из скопированнных в DevTools браузера
├── diagnostic.py           # Диагностический скрипт для анализа
├── capture/                # Папка с выгруженными из роуетра файлами
│   └── capture-*.pcapng    # Файлы в формате .pcapng
├── results/                # Папка с результатами (создается автоматически)
│   └── domains-*.txt       # Файлы с извлеченными доменами
├── venv/                   # Виртуальное окружение (опционально)
└── README.md               # Этот файл
```

### Содержимое файла

```
HTTPS домены из файла: capture.pcapng
Всего найдено уникальных доменов: 25
==================================================

google.com
stackoverflow.com
youtube.com
rr5.sn-aigl6nek.googlevideo.com
```

## ⚙️ Настройки фильтрации

### Исключаются автоматически:

- **HTTP адреса** (`http://example.com`)
- **IP-адреса** (`192.168.1.1`, `2001:db8::1`)
- **Локальные адреса**:
  - `localhost`
  - `127.x.x.x`
  - `192.168.x.x`
  - `10.x.x.x`
  - `172.16.x.x` - `172.31.x.x`
- **Пути и параметры** (`example.com/path?param=value`)
- **Порты** (`example.com:8080`)

### Сохраняются только:

- ✅ Валидные доменные имена
- ✅ HTTPS трафик
- ✅ Внешние (не локальные) адреса


# Извлечение адресов при копировании всех адресов из браузера
1. В Google Chrome перейти на заблокированный сайт (лучше это делать с включенным VPN на компьютере)
2. Нажать F12, откроется панель DevTools
3. Перейти на вкладку Сеть (Network)
![image](https://github.com/user-attachments/assets/e0cb9b11-8532-4942-8d47-34edefd91b65)
4. Обновить страницу
5. Правой кнопкой мыши кликнуть на любой адрес и выбра "Копировать все URL"
![image](https://github.com/user-attachments/assets/328d907f-7b50-445c-869c-c9d23e086276)
6. Сохранить скопированные адреса в корне проекта в файле urls.txt
7. Открыть в терминале папку проекта
8. Запустить из папки скрипт `python3 DevTools.py`
<img width="842" alt="SCR-20250611-knmm" src="https://github.com/user-attachments/assets/aeb5ed11-6263-4076-9ee0-7f873ab8a188" />
9. в папке проекта создасться файл с адресами
![image](https://github.com/user-attachments/assets/20ae493a-90b5-4d3c-b2ec-b5626f48445f)

В один файл urls.txt можно собрать адреса со всех нужных сайтов и разделить их названиями сайтов. Например в таком виде

```txt
#youtube
accounts.youtube.com
bollybeat.h5games.usercontent.goog
fonts.googleapis.com
fonts.gstatic.com
googleads.g.doubleclick.net
i.ytimg.com
lh3.googleusercontent.com
play.google.com
rr3---sn-aigl6nsk.googlevideo.com
static.doubleclick.net
www.google.com
www.gstatic.com
www.youtube.com
yt3.ggpht.com


#x
api.x.com
twimg.com
```
В таком случае в итоговом файле адреса так же будут разделены на сайты и будет понятно, какой URL к какому сайту относится.




### Частые проблемы:

**ModuleNotFoundError: No module named 'pyshark'**

```bash
# Убедитесь, что активировано виртуальное окружение
source venv/bin/activate
pip install pyshark
```

**tshark not found**

```bash
# Проверьте установку Wireshark
tshark --version
# Если не найден, переустановите Wireshark
```


## 📝 Лицензия

Этот проект распространяется под лицензией MIT. См. файл `LICENSE` для подробностей.

## 🔗 Полезные ссылки

- [Wireshark Download](https://www.wireshark.org/download.html)
- [PyShark Documentation](https://kiminewt.github.io/pyshark/)
- [PCAPNG Format Specification](https://tools.ietf.org/html/draft-tuexen-opsawg-pcapng-02)
- [Keenetic Router Manual](https://help.keenetic.com/)

## ❓ FAQ

**Q: Можно ли анализировать файлы .pcap?**
A: Да, PyShark поддерживает оба формата - .pcap и .pcapng.

**Q: Безопасно ли использовать скрипт?**
A: Скрипт только читает файлы захвата и не выполняет сетевых подключений. Однако будьте осторожны с файлами из недоверенных источников.

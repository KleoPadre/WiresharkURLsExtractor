from collections import defaultdict

try:
    with open("urls.txt", "r", encoding="utf-8") as f:
        lines = f.readlines()
except FileNotFoundError:
    print("❌ Файл urls.txt не найден.")
    exit(1)

# Словарь: группа (например, #youtube) -> множество доменов
grouped_domains = defaultdict(set)
current_group = "#unsorted"  # если нет заголовка — всё пойдёт сюда

for line in lines:
    line = line.strip()

    # Пропускаем пустые строки
    if not line:
        continue

    # Если строка начинается с # — это имя группы
    if line.startswith("#"):
        current_group = line
        continue

    # Пропускаем data:image и прочие неполные адреса
    if not (line.startswith("http://") or line.startswith("https://")):
        continue

    try:
        domain = line.split("//")[1].split("/")[0]
        grouped_domains[current_group].add(domain)
    except IndexError:
        continue  # пропускаем некорректные строки

# Пишем результат
with open("domains.txt", "w", encoding="utf-8") as f:
    for group, domains in grouped_domains.items():
        f.write(group + "\n")
        for domain in sorted(domains):
            f.write(domain + "\n")
        f.write("\n")  # пустая строка между группами

print(f"✅ Готово! Найдено {sum(len(v) for v in grouped_domains.values())} уникальных доменов в {len(grouped_domains)} группах. Список в domains.txt")

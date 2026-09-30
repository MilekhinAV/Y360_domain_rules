"""Интерактивное управление доменами в правилах Яндекс 360."""

import copy
import json
import os
import re
import sys

import requests

ORG_ID = os.getenv("Y360_ORG_ID", "ваш_org_id")
OAUTH_TOKEN = os.getenv("Y360_OAUTH_TOKEN", "ваш_oauth_токен")
API_URL = f"https://api360.yandex.net/admin/v1/org/{ORG_ID}/mail/routing/policies"
HEADERS = {
    "Authorization": f"OAuth {OAUTH_TOKEN}",
    "Content-Type": "application/json",
    "Accept": "application/json",
}
TIMEOUT = 30


def show(value):
    print(json.dumps(value, indent=2, ensure_ascii=False))


def get_rules():
    response = requests.get(API_URL, headers=HEADERS, timeout=TIMEOUT)
    if response.status_code != 200:
        raise ValueError(f"Не удалось получить правила: HTTP {response.status_code}.")
    data = response.json()
    rules = data.get("rules") if isinstance(data, dict) else None
    if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
        raise ValueError("API вернул некорректный список правил. Изменения остановлены.")
    return rules


def normalize_domain(value):
    value = value.strip().lower().rstrip(".")
    wildcard = value.startswith("*.")
    host = value[2:] if wildcard else value
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Некорректный домен.") from None
    labels = host.split(".")
    if (len(host) > 253 or (not wildcard and len(labels) < 2)
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x)
                   for x in labels)):
        raise ValueError("Введите домен без адреса почты и URL: example.com или *.us.")
    return ("*." if wildcard else "") + host


def choose(prompt, options):
    while True:
        answer = input(prompt).strip().lower()
        if answer in options:
            return options[answer]
        print("Неверный выбор. Повторите ввод.")


def domain_list(rule):
    condition = rule.get("condition") or {}
    domain_filter = condition.get("domain_filter") or {}
    domains = domain_filter.get("list")
    return domains if isinstance(domains, list) else None


def select_rule(rules):
    candidates = [i for i, rule in enumerate(rules)
                  if domain_list(rule) is not None
                  and (rule.get("action") or {}).get("type") == "reject"]
    if not candidates:
        return None
    if len(candidates) == 1:
        return candidates[0]
    print("\nВыберите правило для изменения:")
    for i in candidates:
        rule = rules[i]
        print(f"{i + 1}. {rule.get('name', 'Без имени')} — {rule.get('action')}")
    return choose("Номер правила: ", {str(i + 1): i for i in candidates})


def run():
    if not ORG_ID.isdigit() or not OAUTH_TOKEN or OAUTH_TOKEN == "ваш_oauth_токен":
        raise ValueError("Укажите Y360_ORG_ID и Y360_OAUTH_TOKEN в окружении или настройках скрипта.")

    original = get_rules()
    print("Текущие правила:")
    show(original)
    index = select_rule(original)
    if index is not None:
        print("\nИзменяемое правило:")
        show(original[index])
    else:
        print("\nДоменного правила блокировки нет. При добавлении будет создано правило блокировки (reject).")

    while True:
        value = input("\nДомен (например example.com или *.us; Enter — выход): ")
        if not value.strip():
            print("Отменено. Правила не изменены.")
            return 0
        try:
            domain = normalize_domain(value)
            break
        except ValueError as error:
            print(error)

    operation = choose("1 — Добавить, 2 — Удалить, 0 — Выход: ", {
        "1": "add", "добавить": "add", "2": "remove", "удалить": "remove",
        "0": "cancel", "выход": "cancel",
    })
    if operation == "cancel":
        print("Отменено. Правила не изменены.")
        return 0

    updated = copy.deepcopy(original)
    if index is None:
        if operation == "remove":
            print("Доменного правила блокировки нет. Удалять нечего.")
            return 0
        if len(updated) >= 200:
            raise ValueError("Достигнут лимит: 200 правил.")
        index = len(updated)
        updated.append({
            "name": "Blocked domains", "description": "Домены, заблокированные через CLI",
            "enabled": True, "condition": {"domain_filter": {"list": []}},
            "action": {"type": "reject"},
        })
    domains = domain_list(updated[index])
    matches = [item for item in domains if normalize_domain(item) == domain]
    if operation == "add" and matches:
        print("Домен уже есть в правиле. Изменения не требуются.")
        return 0
    if operation == "remove" and not matches:
        print("Домен отсутствует в правиле. Изменения не требуются.")
        return 0
    if operation == "add":
        if len(domains) >= 200:
            raise ValueError("Достигнут лимит: 200 доменов в правиле.")
        domains.append(domain)
    else:
        domains[:] = [item for item in domains if item not in matches]

    removed_rule = not domains
    print(f"\n{'Добавить' if operation == 'add' else 'Удалить'} домен: {domain}")
    if removed_rule:
        print(f"Это последний домен. Правило «{updated[index].get('name', 'Без имени')}» будет удалено.")
        updated.pop(index)
    else:
        print("Правило после изменения:")
        show(updated[index])
    if input("Подтвердить? [да/НЕТ]: ").strip().lower() not in {"да", "yes", "y"}:
        print("Отменено. Правила не изменены.")
        return 0

    # PUT заменяет весь список. Не затираем изменения, сделанные за время диалога.
    if get_rules() != original:
        raise ValueError("Правила на сервере изменились. Запустите скрипт заново.")
    try:
        response = requests.put(API_URL, headers=HEADERS, json={"rules": updated}, timeout=TIMEOUT)
    except requests.RequestException:
        raise ValueError("Не получен ответ на сохранение. Результат неизвестен; проверьте правила повторным запуском.") from None
    if response.status_code != 200:
        raise ValueError(f"Сохранение не подтверждено: HTTP {response.status_code}. Проверьте текущие правила.")
    try:
        actual = get_rules()
    except (requests.RequestException, ValueError):
        raise ValueError("API принял изменение, но контрольное чтение не удалось. Проверьте правила повторным запуском.") from None
    if actual != updated:
        print("Текущие правила на сервере:")
        show(actual)
        raise ValueError("Контрольный список отличается от отправленного. Выполнение не подтверждено.")
    print(f"\nВыполнено: домен {domain} {'добавлен' if operation == 'add' else 'удалён'}.")
    if removed_rule:
        print("Пустое правило удалено. Обновлённый список правил:")
        show(actual)
    else:
        print("Обновлённое правило с сервера:")
        show(actual[index])
    return 0


def main():
    try:
        return run()
    except (KeyboardInterrupt, EOFError):
        print("\nВвод прерван. Если сохранение уже началось, проверьте правила повторным запуском.")
        return 1
    except requests.RequestException:
        print("Ошибка соединения с API. Не удалось получить правила.")
        return 1
    except ValueError as error:
        print(f"Ошибка: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())

# Источники и лицензии

Проверка источников выполнена 2026-11-06. Рабочий анализ не обращается к этим адресам.

| Материал | Происхождение / версия | Использование и лицензия |
|---|---|---|
| ATT&CK Enterprise STIX | MITRE attack-stix-data, tag v18.0 | Локальные определения и исторический контекст; MITRE license, полный текст в docs/licenses/MITRE-ATTACK.txt |
| Демонстрационная выборка | Прямое извлечение объектов из указанного STIX | Оригинальные STIX поля сохранены, локально добавлена provenance; не полный граф ссылок |
| Исторические примеры | Три relationship uses из того же MITRE STIX | Контекст, не доказательства текущего случая; не собственные отчёты о расследованиях |
| Qwen GGUF | Qwen/Qwen2.5-1.5B-Instruct-GGUF | Apache-2.0; модель не включена в исходный архив |
| llama-cpp-python | v0.3.18 | MIT; docs/licenses/LLAMA-CPP-PYTHON.txt |
| Локальная инструкция | knowledge/runbook.md v1.0 | Создана для прототипа, CC0-1.0 |
| Синтетический корпус | scripts/make_corpus.py v1.0 | Создан для прототипа, CC0-1.0; не настоящая телеметрия Wazuh/OTRF |
| Программный код | Этот проект | MIT, файл LICENSE |

MITRE: © 2025 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
При распространении снимков сохраняйте copyright и лицензию MITRE.

Официальные адреса:

- https://github.com/mitre-attack/attack-stix-data/tree/v18.0
- https://raw.githubusercontent.com/mitre-attack/attack-stix-data/v18.0/enterprise-attack/enterprise-attack.json
- https://attack.mitre.org/resources/terms-of-use/
- https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/tree/91cad51170dc346986eccefdc2dd33a9da36ead9
- https://github.com/abetlen/llama-cpp-python/tree/v0.3.18
- https://abetlen.github.io/llama-cpp-python/whl/cpu/llama-cpp-python/

Зафиксированная модель:

- файл qwen2.5-1.5b-instruct-q4_k_m.gguf;
- revision 91cad51170dc346986eccefdc2dd33a9da36ead9;
- SHA-256 6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e;
- размер 1117320736 байт;
- model card сохранён в docs/licenses/MODEL-CARD.md.

Установка проверяет SHA-256 модели по LFS-метаданным фиксированной ревизии.
Хеш исходного STIX и извлечённой выборки сохранены в knowledge/manifest.json.
Состав и хеши входов фиксируются отдельно от эталонов в экспериментальном плане/результатах.

Зависимости Python имеют собственные лицензии. Прямые версии зафиксированы в pyproject.toml,
набор установленных версий — requirements-lock.txt, необязательный рантайм — requirements-llm.txt.
Windows-зависимость colorama указана условно; весь Linux freeze не считается проверкой Windows.

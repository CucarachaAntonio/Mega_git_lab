# Mega_git_lab

## Локальный ассистент анализа событий ИБ

Исходники, документация, тесты и примеры: [local-soc-assistant](local-soc-assistant/README.md).

После скачивания репозитория откройте PowerShell в папке `local-soc-assistant`:

```powershell
cd local-soc-assistant
powershell -ExecutionPolicy Bypass -File .\scripts\Setup.ps1 -FullAttack
.\scripts\Start.ps1
```

Нужен Python 3.12 x64. Установка скачивает зависимости, CPU-модель и полный ATT&CK;
последующий анализ работает локально. Для быстрого запуска режима C без модели:
`Setup.ps1 -DemoOnly`.

Версия **0.2.0**: точные ссылки на исходные поля, независимая проверка сохранённого
черновика, раздельные проверки ATT&CK/наблюдений, приоритет и применимость рекомендаций.
В эксперименте B и D используют один Draft.

[Проверки и ограничения](local-soc-assistant/docs/VALIDATION.md):
88 тестов прошли; 3 теста реальной LLM пропущены. Выполнены CLI demo/verify,
24 случая C и 100 механических результатов A/B/C/D на сохранённых черновиках.
Текущий прогон не оценивает качество LLM; Windows не проверялась.

[Глава 2: архитектура](local-soc-assistant/docs/ARCHITECTURE.md) ·
[Глава 3: эксперимент](local-soc-assistant/docs/EXPERIMENT.md) ·
[Связь с литературой](local-soc-assistant/docs/THESIS-TRACEABILITY.md)

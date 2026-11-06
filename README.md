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

[Фактически выполненные проверки и ограничения](local-soc-assistant/docs/VALIDATION.md):
59 быстрых и 3 реальных интеграционных теста. Windows здесь не проверялась.
На одном настроечном сценарии режим D избыточно отказывал; превосходство D не заявляется.

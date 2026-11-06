# Windows: установка, запуск и проверка

## Подготовка

1. Windows x64, Python 3.12 x64 с python.org. При установке включить py launcher.
2. Распаковать проект в каталог для записи, например `D:\Projects\local-soc-assistant`.
3. Запустить PowerShell в этой папке. Установку проводить с интернетом.

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Setup.ps1
.\scripts\Check.ps1 -RealLLM
.\scripts\Start.ps1
```

Открыть http://127.0.0.1:8501. Остановить сервер: Ctrl+C.
Ничего не устанавливается во время анализа. Скрипты определяют свой каталог и не требуют активации venv.
`Setup.ps1 -DemoOnly` пропускает LLM; `Setup.ps1 -FullAttack` дополнительно получает полный официальный STIX,
переключает путь снимка и строит соответствующий индекс.

## Эквивалентные команды

```powershell
py -3.12 -m venv .venv
$PythonExe = ".\.venv\Scripts\python.exe"
& $PythonExe -m pip install -r requirements-lock.txt
& $PythonExe -m pip install --no-build-isolation --no-deps -e .
& $PythonExe -m pip install -r requirements-llm.txt --only-binary=llama-cpp-python --extra-index-url https://abetlen.github.io/llama-cpp-python/whl/cpu
& $PythonExe -m soc_assistant.cli prepare --model
& $PythonExe -m soc_assistant.cli prepare --index
& $PythonExe -m soc_assistant.cli ready --require-llm
& $PythonExe -m streamlit run app.py --server.address 127.0.0.1 --browser.gatherUsageStats false
```

CPU wheel для llama-cpp-python 0.3.18 перечислен в официальном индексе для cp311/cp312 win_amd64.
Сам факт наличия wheel не подтверждает запуск на конкретном процессоре/Windows.
При ошибке DLL проверьте установленный Microsoft Visual C++ Redistributable x64.
При отсутствии совместимого wheel можно собрать ту же версию через поддерживаемые инструменты:
Visual Studio Build Tools 2022, workload «Desktop development with C++», CMake, x64 Native Tools shell.

```powershell
$env:CMAKE_ARGS = "-DGGML_CUDA=OFF -DGGML_NATIVE=OFF -DLLAMA_CURL=OFF"
& .\.venv\Scripts\python.exe -m pip install --no-binary=llama-cpp-python llama-cpp-python==0.3.18
Remove-Item Env:CMAKE_ARGS
```

Сборка из исходников — запасной путь; Docker/WSL не обязательны.

## Проверка автономности и ресурсов

После полной подготовки отключите интернет и выполните:

```powershell
.\scripts\Check.ps1 -RealLLM
.\.venv\Scripts\python.exe -m soc_assistant.cli demo --mode D --out data\offline-D
.\scripts\Start.ps1
```

В браузере загрузите демо, выполните A/B/C/D, откройте историю и выгрузите HTML.
Проверьте, что интерфейс загружается без удалённых ресурсов.
В отчётах сопоставьте среду, доступную RAM, RSS, время загрузки и этапов.
На 16 ГБ начните с исходной модели, top_k=4 и коротких случаев; не запускайте вторую LLM.
При превышении контекста уменьшите окно/число событий/top_k. Не повышайте контекст без измерения памяти.
Если система активно использует pagefile, уменьшайте нагрузку и повторяйте измерения.
Не переносите результаты Linux-стенда на Windows как обещание скорости.

## Linux для разработки

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m pip install --no-build-isolation --no-deps -e .
.venv/bin/python -m soc_assistant.cli prepare --index
.venv/bin/python -m pytest -q -m 'not integration'
```

Если Linux wheel требует недоступный musl, используйте сборку из исходников на glibc:

```bash
CC=gcc CXX=g++ CMAKE_ARGS='-DGGML_CUDA=OFF -DGGML_NATIVE=OFF -DGGML_OPENMP=OFF -DGGML_BLAS=OFF -DLLAMA_CURL=OFF' \
CMAKE_BUILD_PARALLEL_LEVEL=4 .venv/bin/python -m pip install --no-binary=llama-cpp-python llama-cpp-python==0.3.18
```

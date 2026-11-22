# Проектные решения и материалы для ВКР

Тема: «Разработка локального интеллектуального ассистента для анализа и приоритизации
событий информационной безопасности с верификацией рекомендаций по MITRE ATT&CK».
Индивидуальное задание, обновлённая глава 1 и PDF Kotenko/Chechulin в рабочей папке
не обнаружены. Требования доработки взяты из предоставленного текстового задания.

Библиографические ориентиры ниже предоставлены пользователем. Таблица связывает их
с принятыми решениями, но не является новым обзором полных текстов. Полные тексты
в этой доработке не перечитывались; номера страниц и чужие измерения не выдумываются.

| Ориентир | Связь с реализацией | Проверяемый артефакт |
|---|---|---|
| [Милославская](https://link.springer.com/chapter/10.1007/978-3-319-63940-6_40) | Разделение приёма, нормализации, корреляции, анализа и представления SIEM | Модули и поток в ARCHITECTURE.md |
| [Benzekri et al., CSNet 2019](https://dblp1.uni-trier.de/db/conf/csnet/csnet2019.html) | Явные временные условия корреляции; запись окна и оснований | correlate.py, тесты окна/часов/flow |
| Kotenko, Chechulin, *Attack Modeling and Security Evaluation in SIEM Systems*, 2012, с. 129–147, itssa.0008.2012.041 | Разделение наблюдаемого, инфраструктурного обогащения и возможного развития | Event.raw/field_origins, priority_context(kind=enrichment), hypotheses. PDF не приложен; точные положения полного текста требуют сверки |
| [Jangampet](https://iaeme.com/Home/article_id/IJCET_12_03_009) | Полнота и качество входа, диагностируемая неопределённость времени | ImportIssue, TimeMark, time_state, недостаточность профиля |
| [Ansari](https://svedbergopen.com/index.php/ijaiml/article/view/2929) | Прослеживаемая связь корреляции с очередностью разбора | Case.links, memberships, priority_assessment |
| [Lewis et al.](https://proceedings.neurips.cc/paper/2020/hash/6b493230205f780e1bc26945df7481e5-Abstract.html) | Дополнение генерации локальным поиском | Режимы A/B, Retriever, сохранённые запросы и версии |
| [Ismail et al.](https://www.mdpi.com/1424-8220/25/3/870) | Контекст применения RAG к Wazuh; в прототипе выбраны файловые экспорты | ingest.py, локальный корпус; интеграция с живой SIEM не заявляется |
| [Gao et al., ALCE](https://aclanthology.org/2023.emnlp-main.398/) | Различение наличия ссылки и её содержательной опоры | Отдельные identity_check, observation_check, source_integrity |
| [Min et al., FActScore](https://aclanthology.org/2023.emnlp-main.741/) | Оценка отдельных проверяемых утверждений | Evidence, fact_assessments, независимые assertion_outcomes |
| [Fronesis, NIST](https://www.nist.gov/publications/fronesis-digital-forensics-based-early-detection-ongoing-cyber-attacks) | Явные условия сопоставления наблюдений с ATT&CK | Три версионируемых узких профиля; расширения требуют условий и контролей |
| [Srinivas et al.](https://www.mdpi.com/2624-800X/5/4/95) | Разграничение LLM, поиска и программной оркестрации | Нет инструментов исполнения, отдельных исполнительных агентов или управления инфраструктурой |
| [Kamath et al.](https://aclanthology.org/2020.acl-main.503/) | Совместное измерение отказов и покрытия | Метрики отказов случая и отдельных возможностей заключения |
| [Kapoor, Narayanan](https://pubmed.ncbi.nlm.nih.gov/37720327/) | Защита от утечки эталона | Отдельные gold, family split, фильтрация кодов/меток, отсутствие gold в промпте/индексе |
| [Kausar et al., препринт v2](https://arxiv.org/abs/2601.04243v2) | Совместный учёт ошибок, полноты и задержки | TP/FP/FN, доказательства, отказы, full_pass и verification. Опубликованные числа не используются как результаты прототипа |

Для главы 2 используйте границы модулей, формат наблюдения/черновика/отчёта,
условия связи и верификации из ARCHITECTURE.md и VERIFICATION.md.

Для главы 3 используйте EXPERIMENT.md, evaluation/gold.json (прежний инженерный набор),
evaluation/controls.json (новые контролируемые случаи), исходные записи examples/scenarios/
и examples/controls/, а также протокол validation/upgrade-20261122/. Код расчёта —
soc_assistant/evaluation.py. Данные контроля синтетические. Механический повтор
сохранённых Draft не измеряет качество генерации и не доказывает превосходство D.
Свободные трактовки и пригодность рекомендаций требуют независимой разметки аналитиком.

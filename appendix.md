ПРИЛОЖЕНИЕ 1
Внутренняя структура исходного кода программы pkica

В приложении приведено краткое описание внутренней структуры исходного кода программы pkica. Основное внимание уделено связи командного интерфейса с программными модулями, назначению ключевых частей кода и порядку обработки данных при выполнении основных операций удостоверяющего центра.

1.1 Общая структура проекта

Исходный код программы организован как Python-пакет pkica. Основные модули отвечают за обработку команд CLI, создание Root CA и Intermediate CA, генерацию ключей и CSR, обработку заявок, выпуск и отзыв сертификатов, публикацию CRL, проверку цепочки доверия, экспорт файлов, ведение реестров и аудит.

Общая структура проекта:

```text
pkica/
├── __init__.py
├── cli.py
├── config.py
├── pki/
│   ├── __init__.py
│   ├── ca.py
│   ├── crl.py
│   ├── csr.py
│   ├── inspect.py
│   ├── keys.py
│   └── verify.py
├── policy/
│   ├── __init__.py
│   └── profiles.py
└── storage/
    ├── __init__.py
    ├── audit.py
    ├── export.py
    ├── requests.py
    ├── revocations.py
    ├── secure.py
    └── status.py

tests/
├── test_cli_flow.py
└── test_security.py

scripts/
└── test_full_flow.sh

pyproject.toml
README.md
```

Рабочие данные удостоверяющего центра создаются в каталоге data относительно текущего рабочего каталога. В него помещаются ключи и сертификаты Root CA и Intermediate CA, ключи и CSR субъектов, выпущенные сертификаты, JSON-реестры, CRL, экспортированные файлы и журнал аудита. Путь к этим каталогам и файлам задаётся в модуле pkica.config.

1.2 Связь CLI-команд с внутренним кодом

Основной точкой входа программы является модуль pkica.cli. Он принимает параметры пользователя, определяет выбранную команду и вызывает соответствующую внутреннюю функцию. Сам модуль CLI не содержит низкоуровневую криптографическую реализацию, а выполняет роль связующего слоя между пользователем и внутренними модулями программы.

Таблица 1.1 - Связь CLI-команд с внутренними модулями программы

| CLI-команда | Основные внутренние модули | Назначение |
|---|---|---|
| pkica ca init-root | pkica.cli, pkica.pki.ca, pkica.pki.keys | Создание закрытого ключа и самоподписанного сертификата Root CA |
| pkica ca init-intermediate | pkica.cli, pkica.pki.ca, pkica.pki.keys | Создание Intermediate CA и подпись его сертификата ключом Root CA |
| pkica key gen | pkica.cli, pkica.pki.keys | Генерация ключевой пары субъекта |
| pkica csr gen | pkica.cli, pkica.pki.csr | Формирование CSR субъекта |
| pkica req submit | pkica.cli, pkica.storage.requests | Создание заявки на выпуск сертификата по CSR |
| pkica req list | pkica.cli, pkica.storage.requests | Просмотр списка заявок |
| pkica req approve | pkica.cli, pkica.storage.requests | Одобрение заявки |
| pkica req reject | pkica.cli, pkica.storage.requests | Отклонение заявки с фиксацией причины |
| pkica cert issue | pkica.cli, pkica.pki.ca, pkica.policy.profiles | Выпуск конечного X.509-сертификата по CSR или одобренной заявке |
| pkica cert show | pkica.cli, pkica.pki.inspect | Просмотр сведений о сертификате |
| pkica cert list | pkica.cli, pkica.pki.ca | Просмотр реестра выпущенных сертификатов |
| pkica cert revoke | pkica.cli, pkica.pki.ca, pkica.storage.revocations | Отзыв сертификата и изменение его статуса в реестре |
| pkica crl publish | pkica.cli, pkica.pki.crl, pkica.storage.revocations | Публикация CRL по реестру отозванных сертификатов |
| pkica verify | pkica.cli, pkica.pki.verify | Проверка цепочки доверия и статуса отзыва |
| pkica export trust | pkica.cli, pkica.storage.export | Экспорт Root CA, Intermediate CA и цепочки доверия |
| pkica export nginx | pkica.cli, pkica.storage.export | Экспорт активного server_tls-сертификата и цепочки для Nginx |
| pkica status | pkica.cli, pkica.storage.status | Просмотр состояния УЦ, заявок, сертификатов и CRL |
| pkica reset | pkica.cli, pkica.config | Очистка тестовой среды и пересоздание базовой структуры каталогов |

Разбор аргументов выполняется функцией pkica.cli.build_parser. После разбора argparse сохраняет в объекте args ссылку на обработчик команды через set_defaults(func=...). Функция pkica.cli.main вызывает args.func(args), поэтому каждая CLI-команда имеет отдельную функцию-обработчик.

1.3 Назначение основных модулей

В данном разделе кратко описываются основные файлы исходного кода и их роль в программе.

Таблица 1.2 - Назначение основных модулей программы

| Модуль | Назначение |
|---|---|
| pkica.cli | Разбор CLI-команд, проверка пользовательских параметров, вызов внутренних функций, печать результата и запись событий аудита |
| pkica.config | Описание путей к рабочим каталогам и файлам data, создание структуры каталогов, настройка приватных прав доступа для чувствительных директорий |
| pkica.pki.keys | Генерация RSA или ECDSA закрытых ключей, сохранение ключей в PEM с возможным шифрованием, загрузка PEM-ключей |
| pkica.pki.csr | Формирование subject, SAN-расширения и CSR субъекта, сохранение и загрузка CSR |
| pkica.pki.ca | Создание Root CA, создание CSR Intermediate CA, подпись сертификата Intermediate CA, выпуск конечных сертификатов, сохранение сертификатов и fullchain, работа с реестром issued.json |
| pkica.pki.crl | Формирование CRL, преобразование причин отзыва в x509.ReasonFlags, добавление записей RevokedCertificate, подпись и сохранение CRL |
| pkica.pki.verify | Проверка цепочки доверия: сроки действия, issuer/subject, BasicConstraints, KeyUsage, EKU, path length, подписи сертификатов, подпись и метаданные CRL, наличие сертификата в CRL |
| pkica.pki.inspect | Извлечение человекочитаемых сведений из сертификата: CN, SAN, EKU, BasicConstraints, KeyUsage |
| pkica.policy.profiles | Проверка CSR под профили server_tls и client_tls, построение расширений конечного сертификата |
| pkica.storage.requests | Создание, загрузка и сохранение заявок; копирование CSR в data/requests; переходы статусов pending, approved, rejected, issued |
| pkica.storage.revocations | Ведение revoked.json, добавление записей об отзыве, проверка повторного отзыва |
| pkica.storage.audit | Запись событий в audit.log в формате JSON Lines |
| pkica.storage.export | Копирование сертификатов и сборка цепочек для экспорта |
| pkica.storage.secure | Атомарная запись приватных файлов, добавление в защищённые текстовые файлы, выставление прав 0600 для файлов и 0700 для директорий |
| pkica.storage.status | Загрузка JSON-списков и подсчёт записей по статусам |

1.4 Основные последовательности выполнения операций

В этом разделе показаны ключевые сценарии работы кода. Для каждого сценария приведена общая последовательность обработки и краткое пояснение роли основных модулей.

1.4.1 Создание Root CA и Intermediate CA

```text
Команда pkica ca init-root
    ↓
pkica.cli.command_init_root
    ↓
pkica.config.ensure_ca_directories
    ↓
pkica.pki.ca.parse_subject
    ↓
pkica.pki.keys.generate_private_key
    ↓
pkica.pki.ca.create_root_ca_certificate
    ↓
pkica.pki.keys.save_private_key
    ↓
pkica.pki.ca.save_certificate
    ↓
pkica.storage.audit.append_jsonl
```

```text
Команда pkica ca init-intermediate
    ↓
pkica.cli.command_init_intermediate
    ↓
Загрузка ключа Root CA и сертификата Root CA
    ↓
Генерация ключа Intermediate CA
    ↓
pkica.pki.ca.create_intermediate_csr
    ↓
pkica.pki.ca.create_intermediate_ca_certificate
    ↓
Сохранение ключа, CSR и сертификата Intermediate CA
    ↓
pkica.storage.audit.append_jsonl
```

Root CA создаётся как самоподписанный сертификат, а Intermediate CA выпускается по CSR и подписывается ключом Root CA. В этом сценарии pkica.cli управляет пользовательскими параметрами, pkica.pki.keys создаёт и сохраняет ключи, pkica.pki.ca формирует сертификаты, а pkica.storage.audit фиксирует события в журнале аудита.

1.4.2 Выпуск сертификата

```text
Команда pkica cert issue
    ↓
pkica.cli.command_cert_issue
    ↓
Выбор источника CSR: --req-id или --csr
    ↓
Если используется --req-id: загрузка requests.json и проверка статуса approved
    ↓
Проверка CSR и выбор профиля server_tls или client_tls
    ↓
Загрузка ключа и сертификата Intermediate CA
    ↓
Формирование и подпись конечного сертификата
    ↓
Сохранение .crt.pem и .fullchain.pem
    ↓
pkica.pki.ca.append_issued_record
    ↓
Если сертификат выпущен по заявке: pkica.storage.requests.mark_request_issued
```

Сертификат может выпускаться напрямую по CSR или по ранее одобренной заявке. Профили server_tls и client_tls задают набор расширений X.509 и проверяются в pkica.policy.profiles, а подпись конечного сертификата выполняется ключом Intermediate CA в pkica.pki.ca. После выпуска программа сохраняет сертификат, fullchain-файл и обновляет JSON-реестры.

1.4.3 Отзыв сертификата и публикация CRL

```text
Команда pkica cert revoke
    ↓
pkica.cli.command_cert_revoke
    ↓
Поиск сертификата в issued.json
    ↓
Добавление записи в revoked.json
    ↓
Изменение статуса сертификата на revoked
```

Отзыв выполняется по серийному номеру сертификата. Программа находит запись в issued.json, фиксирует причину и время отзыва в revoked.json, после чего изменяет статус сертификата в реестре выданных сертификатов.

```text
Команда pkica crl publish
    ↓
pkica.cli.command_crl_publish
    ↓
Загрузка ключа и сертификата Intermediate CA
    ↓
Загрузка revoked.json
    ↓
Формирование и подпись CRL
    ↓
Сохранение data/crl/intermediate.crl.pem
```

CRL формируется на основе revoked.json и подписывается закрытым ключом Intermediate CA. В список попадают серийные номера отозванных сертификатов, даты и причины отзыва.

1.4.4 Проверка сертификата

```text
Команда pkica verify
    ↓
pkica.cli.command_verify
    ↓
Выбор CRL: --no-crl, --crl или data/crl/intermediate.crl.pem
    ↓
Загрузка сертификата, Intermediate CA и Root CA
    ↓
Проверка цепочки доверия, сроков, расширений и подписей
    ↓
Если CRL задан: проверка статуса отзыва
    ↓
Запись результата в audit.log
```

Проверка выполняется в pkica.pki.verify. Модуль контролирует корректность цепочки Root CA - Intermediate CA - конечный сертификат, сроки действия, основные X.509-расширения и криптографические подписи. Если опубликован CRL или он указан явно, дополнительно проверяется, что сертификат не входит в список отозванных.

1.5 Работа с реестрами и аудитом

Состояние программы хранится в JSON-реестрах. Они используются для учёта заявок, выпущенных сертификатов, отозванных сертификатов и текущего состояния удостоверяющего центра.

Таблица 1.3 - Основные служебные файлы программы

| Файл или каталог | Назначение |
|---|---|
| data/db/requests.json | Реестр заявок на выпуск сертификатов |
| data/requests/req-000001.csr.pem и последующие файлы | Сохранённые копии CSR, привязанные к заявкам |
| data/db/issued.json | Реестр выпущенных сертификатов с серийным номером, профилем, subject, issuer, сроками, путями и статусом |
| data/db/revoked.json | Реестр отозванных сертификатов с серийным номером, причиной, путём к сертификату и временем отзыва |
| data/audit/audit.log | Журнал аудита в формате JSON Lines |
| data/ca/root/private/root.key.pem | Закрытый ключ Root CA |
| data/ca/root/certs/root.crt.pem | Сертификат Root CA |
| data/ca/intermediate/private/intermediate.key.pem | Закрытый ключ Intermediate CA |
| data/ca/intermediate/csr/intermediate.csr.pem | CSR Intermediate CA |
| data/ca/intermediate/certs/intermediate.crt.pem | Сертификат Intermediate CA |
| data/subjects/keys/ | Закрытые ключи субъектов |
| data/subjects/csrs/ | CSR субъектов |
| data/issued/ | Выпущенные сертификаты и fullchain-файлы |
| data/crl/intermediate.crl.pem | Опубликованный список отозванных сертификатов |
| data/export/trust/ | Экспорт Root CA, Intermediate CA и ca-chain.pem |
| data/export/nginx/<serial>/ | Экспорт server_tls-сертификата и цепочки для Nginx |

Заявки обслуживает модуль pkica.storage.requests. Функция submit_request загружает текущий список заявок, вычисляет следующий ID, загружает CSR, копирует его в data/requests и сохраняет запись со статусом pending. Функция update_request_status переводит заявку в approved или rejected и фиксирует время изменения. Функция mark_request_issued переводит одобренную заявку в issued и записывает серийный номер выпущенного сертификата.

Реестр issued.json обслуживается функциями pkica.pki.ca.load_issued_records, append_issued_record, find_issued_record_by_serial, find_issued_record_by_request_id, save_issued_records и mark_issued_record_revoked. Реестр revoked.json обслуживается функциями pkica.storage.revocations.load_revocations, save_revocations, is_revoked и add_revocation.

Аудит реализован в pkica.storage.audit.append_jsonl. Каждое событие дополняется timestamp в UTC и записывается отдельной JSON-строкой. В аудит попадают операции ca.init_root, ca.init_intermediate, key.gen, csr.gen, req.submit, req.approve, req.reject, cert.issue, cert.revoke, crl.publish, verify, export.trust, export.nginx, status и reset.

Для чувствительных файлов используется модуль pkica.storage.secure. Он задаёт права 0600 для приватных файлов и 0700 для приватных каталогов. Функции write_private_bytes и write_private_text записывают данные через временный файл и последующую замену, что снижает риск повреждения JSON-реестров и ключевых файлов при ошибке записи.

1.6 Тестовый код

Тестовый код используется для проверки внутренних функций и полного сценария работы программы. Тесты создают изолированное временное окружение, запускают команды через python -m pkica.cli и проверяют появление ожидаемых файлов, изменение реестров, корректность выпуска, проверки, отзыва сертификатов и публикации CRL.

Таблица 1.4 - Назначение тестовых файлов

| Файл | Назначение |
|---|---|
| tests/test_cli_flow.py | Проверка основного CLI-сценария и типовых ошибок команд |
| tests/test_security.py | Проверка прав доступа, CRL, ограничений сроков, статусов заявок, повторного отзыва, SAN/EKU и корректности цепочки доверия |
| scripts/test_full_flow.sh | Проверка полного сценария работы УЦ через CLI с зашифрованными ключами, несколькими серверными и клиентским сертификатом, экспортом, отзывом, CRL и финальным status |

В pyproject.toml проект объявлен как пакет pkica версии 0.1.0. Единственная внешняя зависимость приложения - cryptography версии 42.0.0 или новее. Точка входа CLI зарегистрирована как консольная команда pkica, которая вызывает pkica.cli:main.

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

| CLI-команда | Внутренняя функция или модуль | Назначение |
|---|---|---|
| pkica ca init-root | pkica.cli.command_init_root; pkica.pki.ca.create_root_ca_certificate; pkica.pki.keys.generate_private_key | Создание закрытого ключа и самоподписанного сертификата Root CA |
| pkica ca init-intermediate | pkica.cli.command_init_intermediate; pkica.pki.ca.create_intermediate_csr; pkica.pki.ca.create_intermediate_ca_certificate | Создание Intermediate CA и подпись его сертификата ключом Root CA |
| pkica key gen | pkica.cli.command_key_gen; pkica.pki.keys.generate_private_key; pkica.pki.keys.save_private_key | Генерация ключевой пары субъекта |
| pkica csr gen | pkica.cli.command_csr_gen; pkica.pki.csr.create_csr; pkica.pki.csr.save_csr | Формирование CSR субъекта с CN, организацией, страной и SAN |
| pkica req submit | pkica.cli.command_req_submit; pkica.storage.requests.submit_request | Создание заявки на выпуск сертификата по CSR |
| pkica req list | pkica.cli.command_req_list; pkica.storage.requests.load_requests | Просмотр списка заявок и фильтрация по статусу |
| pkica req approve | pkica.cli.command_req_approve; pkica.storage.requests.update_request_status | Одобрение заявки |
| pkica req reject | pkica.cli.command_req_reject; pkica.storage.requests.update_request_status | Отклонение заявки с фиксацией причины |
| pkica cert issue | pkica.cli.command_cert_issue; pkica.policy.profiles.validate_csr_for_profile; pkica.policy.profiles.build_end_entity_extensions; pkica.pki.ca.create_end_entity_certificate | Выпуск конечного X.509-сертификата по CSR или одобренной заявке |
| pkica cert show | pkica.cli.command_cert_show; pkica.pki.inspect | Просмотр сведений о сертификате, расширениях и путях к файлам |
| pkica cert list | pkica.cli.command_cert_list; pkica.pki.ca.load_issued_records | Просмотр реестра выпущенных сертификатов |
| pkica cert revoke | pkica.cli.command_cert_revoke; pkica.storage.revocations.add_revocation; pkica.pki.ca.mark_issued_record_revoked | Отзыв сертификата и изменение его статуса в реестре |
| pkica crl publish | pkica.cli.command_crl_publish; pkica.pki.crl.create_crl; pkica.pki.crl.save_crl | Публикация CRL по реестру отозванных сертификатов |
| pkica verify | pkica.cli.command_verify; pkica.pki.verify.verify_certificate_chain | Проверка цепочки доверия, сроков, расширений, подписей и статуса отзыва |
| pkica export trust | pkica.cli.command_export_trust; pkica.storage.export.copy_file; pkica.storage.export.write_chain | Экспорт Root CA, Intermediate CA и цепочки доверия |
| pkica export nginx | pkica.cli.command_export_nginx; pkica.storage.export.copy_file | Экспорт активного server_tls-сертификата и цепочки для Nginx |
| pkica status | pkica.cli.command_status; pkica.storage.status.load_json_list; pkica.storage.status.count_by_status | Просмотр состояния УЦ, заявок, сертификатов и CRL |
| pkica reset | pkica.cli.command_reset; pkica.config.ensure_ca_directories | Очистка тестовой среды и пересоздание базовой структуры каталогов |

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

В этом разделе показаны ключевые сценарии работы кода. Последовательности отражают не только порядок CLI-команд, но и то, какие внутренние функции участвуют в обработке.

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

Root CA создаётся функцией command_init_root. Она проверяет, что корневой ключ и сертификат ещё не существуют, создаёт рабочие каталоги, обрабатывает флаг --encrypt, разбирает строку subject функцией parse_subject и генерирует ключ через generate_private_key. Самоподписанный сертификат Root CA формируется в create_root_ca_certificate: subject и issuer совпадают, добавляются BasicConstraints с CA:TRUE и path_length=1, KeyUsage с keyCertSign и cRLSign, SubjectKeyIdentifier. Сертификат подписывается собственным закрытым ключом Root CA.

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

Intermediate CA создаётся функцией command_init_intermediate. Она требует уже существующие файлы Root CA, загружает root.key.pem и root.crt.pem, создаёт отдельный ключ Intermediate CA и CSR для него. Функция create_intermediate_ca_certificate подписывает CSR промежуточного УЦ корневым ключом. В сертификат Intermediate CA добавляются BasicConstraints с CA:TRUE и заданным pathlen, KeyUsage с keyCertSign и cRLSign, SubjectKeyIdentifier и AuthorityKeyIdentifier. Перед выпуском проверяется, что срок действия Intermediate CA не превышает срок действия Root CA.

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
pkica.pki.csr.load_csr
    ↓
pkica.policy.profiles.validate_csr_for_profile
    ↓
Загрузка ключа и сертификата Intermediate CA, загрузка сертификата Root CA
    ↓
pkica.policy.profiles.build_end_entity_extensions
    ↓
pkica.pki.ca.create_end_entity_certificate
    ↓
Сохранение .crt.pem и .fullchain.pem
    ↓
pkica.pki.ca.append_issued_record
    ↓
Если сертификат выпущен по заявке: pkica.storage.requests.mark_request_issued
    ↓
pkica.storage.audit.append_jsonl
```

Профиль сертификата выбирается в command_cert_issue. Если сертификат выпускается по заявке, профиль берётся из записи requests.json. Если выпуск выполняется напрямую по --csr, профиль должен быть указан параметром --profile. Поддерживаются профили server_tls и client_tls.

Проверка CSR выполняется функцией validate_csr_for_profile. Для server_tls требуется корректная подпись CSR и наличие Subject Alternative Name хотя бы с одним DNSName или IPAddress. Для client_tls SAN не обязателен, но подпись CSR также должна быть корректной.

Расширения конечного сертификата создаёт build_end_entity_extensions. Для обоих профилей добавляются BasicConstraints с CA:FALSE, критический KeyUsage, SubjectKeyIdentifier и SAN из CSR, если он присутствует. Для RSA-ключа включается keyEncipherment, для ECDSA-ключа - keyAgreement. Для server_tls добавляется ExtendedKeyUsage serverAuth, для client_tls - clientAuth.

Функция create_end_entity_certificate формирует сертификат по CSR, устанавливает issuer из сертификата Intermediate CA, добавляет подготовленные расширения, добавляет AuthorityKeyIdentifier и подписывает сертификат закрытым ключом Intermediate CA. Перед подписью проверяется, что срок действия конечного сертификата не превышает срок действия Intermediate CA. После выпуска certificate_to_record формирует запись для issued.json, save_fullchain сохраняет цепочку конечный сертификат + Intermediate CA + Root CA.

1.4.3 Отзыв сертификата и публикация CRL

```text
Команда pkica cert revoke
    ↓
pkica.cli.command_cert_revoke
    ↓
pkica.pki.ca.find_issued_record_by_serial
    ↓
pkica.storage.revocations.add_revocation
    ↓
pkica.pki.ca.mark_issued_record_revoked
    ↓
pkica.storage.audit.append_jsonl
```

Отзыв выполняется по серийному номеру сертификата. command_cert_revoke находит запись в issued.json, проверяет, что сертификат ещё не отозван, затем добавляет запись в revoked.json через add_revocation. В запись попадают serial_number, reason, cert_path и revoked_at. После этого mark_issued_record_revoked изменяет запись в issued.json: статус становится revoked, добавляются revoked_at и revocation_reason.

```text
Команда pkica crl publish
    ↓
pkica.cli.command_crl_publish
    ↓
Загрузка ключа и сертификата Intermediate CA
    ↓
pkica.storage.revocations.load_revocations
    ↓
pkica.pki.crl.create_crl
    ↓
pkica.pki.crl.save_crl
    ↓
pkica.storage.audit.append_jsonl
```

Публикация CRL выполняется командой crl publish. Функция create_crl создаёт CertificateRevocationListBuilder, задаёт issuer по сертификату Intermediate CA, last_update и next_update, добавляет AuthorityKeyIdentifier. Для каждой записи revoked.json создаётся RevokedCertificate с серийным номером, датой отзыва и расширением CRLReason. Сопоставление текстовых причин отзыва с x509.ReasonFlags хранится в REASON_MAP. CRL подписывается закрытым ключом Intermediate CA и сохраняется в data/crl/intermediate.crl.pem.

1.4.4 Проверка сертификата

```text
Команда pkica verify
    ↓
pkica.cli.command_verify
    ↓
Выбор CRL: --no-crl, --crl или data/crl/intermediate.crl.pem
    ↓
pkica.pki.verify.verify_certificate_chain
    ↓
Проверка сроков действия
    ↓
Проверка issuer/subject
    ↓
Проверка BasicConstraints, KeyUsage, EKU и path length
    ↓
Проверка подписей конечного, промежуточного и корневого сертификатов
    ↓
Если CRL задан: проверка issuer, сроков, подписи CRL и отсутствия serial в CRL
    ↓
Запись результата в audit.log
```

Функция verify_certificate_chain загружает проверяемый сертификат, Intermediate CA и Root CA. Проверяются сроки действия всех сертификатов, соответствие issuer и subject в цепочке, самоподписанность Root CA, CA-расширения у Root и Intermediate, запрет CA-ролей у конечного сертификата и наличие EKU serverAuth или clientAuth. Подписи проверяются отдельно для RSA и ECDSA. Если используется CRL, дополнительно проверяются issuer CRL, сроки last_update/next_update, подпись CRL и отсутствие серийного номера сертификата среди отозванных.

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
| tests/test_cli_flow.py | Проверка основного CLI-сценария от чистой директории: создание Root CA и Intermediate CA, генерация ключа и CSR, создание и одобрение заявки, выпуск сертификата, просмотр сведений, отзыв, публикация CRL и просмотр статуса |
| tests/test_cli_flow.py | Проверка ошибок CLI: создание Intermediate CA без Root CA, подача отсутствующего CSR, повторная инициализация Root CA |
| tests/test_security.py | Проверка прав доступа к приватным ключам и чувствительным каталогам |
| tests/test_security.py | Проверка поведения verify с CRL по умолчанию, --no-crl, отсутствующим CRL и конфликтующими параметрами --crl и --no-crl |
| tests/test_security.py | Проверка ограничений сроков действия: конечный сертификат не может жить дольше Intermediate CA |
| tests/test_security.py | Проверка автомата состояний заявок: нельзя выпускать pending-заявку, повторно одобрять issued-заявку или отклонять уже выпущенную заявку |
| tests/test_security.py | Проверка повторного отзыва, отсутствующих сертификатов, требования SAN для server_tls и EKU clientAuth для client_tls |
| tests/test_security.py | Проверка низкоуровневой валидации цепочки: CA:TRUE для Intermediate, критичность BasicConstraints и KeyUsage, допустимые EKU, корректные сроки, соответствие issuer/subject и подписи |
| scripts/test_full_flow.sh | Проверка полного сценария работы УЦ через CLI с зашифрованными ключами, несколькими серверными и клиентским сертификатом, экспортом, отзывом, CRL и финальным status |

В pyproject.toml проект объявлен как пакет pkica версии 0.1.0. Единственная внешняя зависимость приложения - cryptography версии 42.0.0 или новее. Точка входа CLI зарегистрирована как консольная команда pkica, которая вызывает pkica.cli:main.

1.7 Вывод по приложению

Исходный код программы pkica построен по модульному принципу. Командный интерфейс отделён от функций, выполняющих основные операции удостоверяющего центра. Отдельные модули отвечают за создание Root CA и Intermediate CA, генерацию ключей и CSR, обработку заявок, выпуск сертификатов, отзыв, публикацию CRL, проверку цепочки доверия, экспорт файлов, работу с JSON-реестрами и аудит.

Такое построение упрощает сопровождение программы и позволяет проследить, какая часть кода отвечает за каждый этап жизненного цикла сертификата: от генерации ключа и CSR до выпуска, проверки, отзыва, публикации CRL и экспорта сертификатов для внешних систем.

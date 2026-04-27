# Методичка по работе с программой `pkica`

## 1. Подготовка окружения

Перейдите в каталог проекта и активируйте виртуальное окружение:

```bash
cd ~/pkica
source .venv/bin/activate
```

Проверьте, что команда доступна:

```bash
pkica --help
```

Если команда не найдена, установите проект в editable-режиме:

```bash
pip install -e .
```

## 2. Инициализация корневого УЦ

Корневой удостоверяющий центр создаёт самоподписанный сертификат и используется для выпуска промежуточного УЦ.

```bash
pkica ca init-root \
  --algo rsa \
  --rsa-bits 4096 \
  --days 3650 \
  --subject "C=RU,O=Rudnev CA,CN=Rudnev Root CA" \
  --encrypt
```

После выполнения будут созданы:

```text
data/ca/root/private/root.key.pem
data/ca/root/certs/root.crt.pem
```

Ключ Root CA сохраняется в зашифрованном виде.

## 3. Инициализация промежуточного УЦ

Промежуточный УЦ подписывается корневым УЦ и используется для выпуска конечных сертификатов.

```bash
pkica ca init-intermediate \
  --algo rsa \
  --rsa-bits 4096 \
  --days 1825 \
  --pathlen 0 \
  --subject "C=RU,O=Rudnev CA,CN=Rudnev Intermediate CA" \
  --encrypt \
  --root-key-encrypted
```

После выполнения будут созданы:

```text
data/ca/intermediate/private/intermediate.key.pem
data/ca/intermediate/csr/intermediate.csr.pem
data/ca/intermediate/certs/intermediate.crt.pem
```

## 4. Проверка состояния системы

Команда `status` показывает текущее состояние УЦ, количество заявок, сертификатов и отзывов. Вызов команды записывается в аудит.

```bash
pkica status
```

Пример вывода:

```text
PKICA status
------------------------------------------------------------
CA initialization
Root CA:         ready
Intermediate CA: ready
CRL:             not published

Requests
Total:           0
Pending:         0
Approved:        0
Issued:          0
Rejected:        0

Certificates
Total issued:    0
Active:          0
Revoked:         0
Revocation DB:   0
```

В выводе также показываются пути к каталогу данных, сертификатам, JSON-реестрам и CRL.

## 5. Выпуск серверного сертификата

### 5.1. Генерация ключа субъекта

Создайте ключ для сервера `web.lab`.

```bash
pkica key gen \
  --name web-server \
  --algo rsa \
  --rsa-bits 2048 \
  --encrypt
```

Файл ключа:

```text
data/subjects/keys/web-server.key.pem
```

### 5.2. Генерация CSR для серверного сертификата

Для серверного TLS-сертификата обязательно нужно указать `SAN`. Профиль `server_tls` требует хотя бы один DNS или IP SAN.

```bash
pkica csr gen \
  --name web-server \
  --key data/subjects/keys/web-server.key.pem \
  --key-encrypted \
  --cn web.lab \
  --org "Rudnev CA" \
  --country RU \
  --san-dns web.lab \
  --san-ip 192.168.56.10
```

Файл CSR:

```text
data/subjects/csrs/web-server.csr.pem
```

### 5.3. Подача заявки на выпуск сертификата

CSR добавляется в реестр заявок.

```bash
pkica req submit \
  --csr data/subjects/csrs/web-server.csr.pem \
  --profile server_tls
```

Программа выведет номер заявки, например:

```text
Request ID: 1
Status:     pending
```

### 5.4. Просмотр списка заявок

```bash
pkica req list
```

Можно отфильтровать заявки по статусу:

```bash
pkica req list --status pending
pkica req list --status approved
pkica req list --status issued
pkica req list --status rejected
```

### 5.5. Одобрение заявки

```bash
pkica req approve --req-id 1
```

После этого заявка переходит в статус:

```text
approved
```

### 5.6. Выпуск сертификата по заявке

```bash
pkica cert issue \
  --req-id 1 \
  --days 365 \
  --intermediate-key-encrypted
```

Программа выведет серийный номер и пути к сертификатам:

```text
Serial:     <serial>
Cert:       data/issued/<serial>.crt.pem
Full chain: data/issued/<serial>.fullchain.pem
```

### 5.7. Просмотр информации о сертификате

По номеру заявки:

```bash
pkica cert show --req-id 1
```

Или по серийному номеру:

```bash
pkica cert show --serial <serial>
```

Для серверного сертификата должны отображаться:

```text
Basic constr.: CA:FALSE
Key Usage:     digitalSignature, keyEncipherment
EKU:           serverAuth
SAN:           DNS:web.lab, IP:192.168.56.10
```

## 6. Выпуск клиентского сертификата

### 6.1. Генерация ключа клиента

```bash
pkica key gen \
  --name client-01 \
  --algo rsa \
  --rsa-bits 2048 \
  --encrypt
```

### 6.2. Генерация CSR клиента

Для клиентского сертификата `SAN` не обязателен.

```bash
pkica csr gen \
  --name client-01 \
  --key data/subjects/keys/client-01.key.pem \
  --key-encrypted \
  --cn client-01 \
  --org "Rudnev CA" \
  --country RU
```

### 6.3. Подача заявки на клиентский сертификат

```bash
pkica req submit \
  --csr data/subjects/csrs/client-01.csr.pem \
  --profile client_tls
```

Например, заявка получила ID `2`.

### 6.4. Одобрение и выпуск клиентского сертификата

```bash
pkica req approve --req-id 2
```

```bash
pkica cert issue \
  --req-id 2 \
  --days 365 \
  --intermediate-key-encrypted
```

Проверка:

```bash
pkica cert show --req-id 2
```

Для клиентского сертификата должно быть:

```text
Basic constr.: CA:FALSE
Key Usage:     digitalSignature
EKU:           clientAuth
```

## 7. Отклонение заявки

Если заявку не нужно выпускать, её можно отклонить:

```bash
pkica req reject \
  --req-id 3 \
  --reason "Invalid certificate request"
```

После этого она получит статус:

```text
rejected
```

Проверка:

```bash
pkica req list --status rejected
```

## 8. Прямой выпуск сертификата без заявки

Для тестирования можно выпустить сертификат напрямую по CSR.

```bash
pkica cert issue \
  --csr data/subjects/csrs/web-server.csr.pem \
  --profile server_tls \
  --days 365 \
  --intermediate-key-encrypted
```

Основной режим для демонстрации УЦ — выпуск через заявки, но прямой режим удобен при отладке.

Срок конечного сертификата не может превышать срок действия Intermediate CA. Если указать слишком большой `--days`, выпуск завершится ошибкой.

## 9. Проверка сертификата

### 9.1. Проверка цепочки без опубликованного CRL

```bash
pkica verify \
  --cert data/issued/<serial>.crt.pem
```

Если цепочка корректна, но CRL ещё не опубликован, будет выведено:

```text
Chain:       valid
CRL:         not checked
Warning:     revocation status was not checked
```

### 9.2. Проверка с учётом CRL

После публикации CRL команда `verify` автоматически использует файл:

```text
data/crl/intermediate.crl.pem
```

Поэтому обычно достаточно выполнить:

```bash
pkica verify \
  --cert data/issued/<serial>.crt.pem
```

Можно явно указать другой CRL:

```bash
pkica verify \
  --cert data/issued/<serial>.crt.pem \
  --crl data/crl/intermediate.crl.pem
```

Если сертификат действителен:

```text
Chain:       valid
CRL:         checked
Revocation:  not revoked
```

Если нужно отключить проверку отзыва, используйте явный флаг:

```bash
pkica verify \
  --cert data/issued/<serial>.crt.pem \
  --no-crl
```

Нельзя одновременно использовать `--crl` и `--no-crl`.

Во время проверки дополнительно контролируются подписи цепочки, сроки действия, соответствие issuer/subject, `BasicConstraints`, `KeyUsage`, CA-роли Root/Intermediate, срок конечного сертификата относительно Intermediate CA, срок и issuer CRL.

## 10. Отзыв сертификата

### 10.1. Отзыв по серийному номеру

```bash
pkica cert revoke \
  --serial <serial> \
  --reason keyCompromise
```

Доступные причины отзыва:

```text
unspecified
keyCompromise
caCompromise
affiliationChanged
superseded
cessationOfOperation
certificateHold
privilegeWithdrawn
aaCompromise
```

После отзыва сертификат получает статус:

```text
revoked
```

Проверить можно так:

```bash
pkica cert show --serial <serial>
```

### 10.2. Публикация CRL

После отзыва нужно сформировать новый список отозванных сертификатов.

```bash
pkica crl publish \
  --days 7 \
  --intermediate-key-encrypted
```

Файл CRL будет сохранён:

```text
data/crl/intermediate.crl.pem
```

Срок CRL не может превышать срок действия Intermediate CA.

Проверить содержимое CRL через OpenSSL:

```bash
openssl crl -in data/crl/intermediate.crl.pem -text -noout
```

### 10.3. Проверка отозванного сертификата

```bash
pkica verify \
  --cert data/issued/<serial>.crt.pem
```

Ожидаемый результат:

```text
Certificate verification failed
------------------------------------------------------------
Reason: Certificate is revoked
```

## 11. Сброс тестовой среды

Команда сброса удаляет все данные УЦ: ключи, сертификаты, заявки, CRL, JSON-реестры и аудит.

Обычный режим с подтверждением:

```bash
pkica reset
```

Для подтверждения нужно ввести:

```text
yes
```

Быстрый режим без подтверждения:

```bash
pkica reset --force
```

После сброса можно заново выполнить полный цикл:

```bash
pkica ca init-root
pkica ca init-intermediate
pkica key gen
pkica csr gen
pkica req submit
pkica req approve
pkica cert issue
pkica cert revoke
pkica crl publish
```

После сброса базовая структура каталогов создаётся заново.

## 12. Рекомендуемый полный сценарий демонстрации

Готовый сценарий находится в `scripts/test_full_flow.sh`. Он проходит полный цикл: создание Root/Intermediate, выпуск серверных и клиентских сертификатов, проверку, экспорт, публикацию CRL, отзыв и проверку отозванного сертификата.

```bash
bash scripts/test_full_flow.sh
```

Скрипт генерирует случайные пароли на каждый запуск. Для воспроизводимого запуска можно передать пароли через переменные окружения:

```bash
ROOT_PASS=... INTER_PASS=... SERVER1_PASS=... SERVER2_PASS=... CLIENT_PASS=... \
  bash scripts/test_full_flow.sh
```

Ниже основной сценарий в ручном виде.

```bash
pkica ca init-root \
  --algo rsa \
  --rsa-bits 4096 \
  --days 3650 \
  --subject "C=RU,O=Rudnev CA,CN=Rudnev Root CA" \
  --encrypt

pkica ca init-intermediate \
  --algo rsa \
  --rsa-bits 4096 \
  --days 1825 \
  --pathlen 0 \
  --subject "C=RU,O=Rudnev CA,CN=Rudnev Intermediate CA" \
  --encrypt \
  --root-key-encrypted

pkica key gen \
  --name web-server \
  --algo rsa \
  --rsa-bits 2048 \
  --encrypt

pkica csr gen \
  --name web-server \
  --key data/subjects/keys/web-server.key.pem \
  --key-encrypted \
  --cn web.lab \
  --org "Rudnev CA" \
  --country RU \
  --san-dns web.lab \
  --san-ip 192.168.56.10

pkica req submit \
  --csr data/subjects/csrs/web-server.csr.pem \
  --profile server_tls

pkica req list

pkica req approve --req-id 1

pkica cert issue \
  --req-id 1 \
  --days 365 \
  --intermediate-key-encrypted

pkica cert show --req-id 1

pkica verify \
  --cert data/issued/<serial>.crt.pem

pkica cert revoke \
  --serial <serial> \
  --reason keyCompromise

pkica crl publish \
  --days 7 \
  --intermediate-key-encrypted

pkica verify \
  --cert data/issued/<serial>.crt.pem

pkica status
```

Где `<serial>` нужно заменить на серийный номер, который программа выведет после команды `cert issue`.

## 13. Аудит

Журнал аудита хранится в:

```text
data/audit/audit.log
```

Формат журнала — JSON Lines: одна JSON-запись на событие. Каждая запись содержит UTC timestamp и поле `action`.

В аудит записываются операции:

```text
ca.init_root
ca.init_intermediate
key.gen
csr.gen
req.submit
req.approve
req.reject
cert.issue
cert.revoke
crl.publish
verify
status
reset
export.trust
export.nginx
```

Для большинства команд запись появляется после успешного выполнения. Для `verify` пишется результат `success` или `failed`.

Просмотр последних событий:

```bash
tail -n 20 data/audit/audit.log
```

## 14. Права доступа и безопасность

- Для Root CA и Intermediate CA используйте `--encrypt`; незашифрованные ключи допустимы только для тестов.
- Сертификат конечного субъекта не может быть выпущен на срок дольше сертификата Intermediate CA.
- CRL не может быть выпущен на срок дольше сертификата Intermediate CA.
- `verify` автоматически проверяет отзыв, если опубликован `data/crl/intermediate.crl.pem`.
- Каталоги `data/ca/root/private`, `data/ca/intermediate/private`, `data/subjects/keys`, `data/db`, `data/audit` создаются с правами `700`.
- Файлы `*.key.pem`, `*.json` и `data/audit/audit.log` сохраняются с правами `600`.
- Профиль `server_tls` требует SAN с DNS или IP.

## 15. Тесты

Тесты запускаются через `pytest`:

```bash
pytest
```

Тесты находятся в `tests/`. Интеграционные сценарии вызывают CLI как `python -m pkica.cli ...` и работают во временных каталогах `tmp_path`, поэтому не изменяют реальные данные проекта в `data/`.

Покрываются базовый CLI flow, ошибочные сценарии, права доступа к чувствительным файлам и каталогам, проверка CRL, отзыв сертификатов, ограничения сроков действия и базовая валидация цепочки сертификатов.

# Развёртывание CryptoLab на ivan

С 31.10.2026 основной стенд <https://lab-06.course.denrad.dev/> работает на
`ivan` (`ivan.denrad.dev`, `89.208.69.52`) в Docker Compose за общим Caddy.
Предыдущее размещение сохранено в [exe-dev.md](exe-dev.md); старый сервис
остановлен. Одновременно включать запись на двух копиях одной базы нельзя.

## Состав и размещение

| Компонент | Файл в репозитории | Путь на сервере |
| --- | --- | --- |
| Исходники и Dockerfile | корень репозитория | `/srv/course/lab06/source/` |
| Compose приложения | [ivan/compose.yaml](ivan/compose.yaml) | `/srv/course/lab06/compose.yaml` |
| Пример переменных | [ivan/runtime.env.example](ivan/runtime.env.example) | `/srv/course/lab06/runtime.env` |
| Compose общего Caddy | [ivan/ingress/compose.yaml](ivan/ingress/compose.yaml) | `/srv/course/ingress/compose.yaml` |
| Маршруты HTTPS | [ivan/ingress/Caddyfile](ivan/ingress/Caddyfile) | `/srv/course/ingress/caddy/Caddyfile` |

Серверные `runtime.env` и `data/` находятся рядом с checkout, вне него.
`data/` содержит `state.sqlite3`, каталоги `ca/` и `service/`. Данные и реальные
секреты в репозиторий и образ не включаются. Пример env содержит пустые значения;
без Telegram-конфигурации сдачи сохраняются без уведомлений.

Compose-проекты: `course-lab06` и `course-ingress`. Внешняя Docker-сеть
`lab06_edge` соединяет Caddy с alias `lab06:8000`. Приложение опубликовано
только на loopback хоста `127.0.0.1:18066`. Наружу выходят порты Caddy:
80/tcp, 443/tcp и 443/udp. Admin API Caddy и Docker socket наружу не публикуются.

Приложение: непривилегированный UID:GID `10001:10001`, read-only rootfs,
отдельный tmpfs, без capabilities, один worker, лимиты 1 ГиБ RAM и 2 CPU.
Один worker нужен, поскольку незавершённые задания и лимиты запросов содержатся
в памяти процесса. SQLite, прогресс и сдачи сохраняются в bind mount `data/`.
Контроль здоровья обращается к `/`, не создавая анонимных API-сеансов.
Логи обоих сервисов ограничены тремя файлами по 10 МБ.

## Первое развёртывание

Команды выполняются на сервере под пользователем с Docker и sudo.
Для нового сервера требуется установить Docker Engine и Compose Plugin.

```sh
sudo install -d -m 750 -o "$(id -un)" -g "$(id -gn)" /srv/course/lab06
cd /srv/course/lab06
git clone https://github.com/softdevtools-course/cryptolab-lab6.git source
cp source/deploy/ivan/compose.yaml compose.yaml
install -m 600 source/deploy/ivan/runtime.env.example runtime.env
sudo install -d -m 700 -o 10001 -g 10001 data
docker network create lab06_edge
docker compose build lab06
```

На существующем ivan эти каталоги и сеть уже есть. Не заменяйте его
`runtime.env` примером, не пересоздавайте сеть и не очищайте `data/`.
Перед запуском заполните переменные локально в `runtime.env`; не печатайте
его содержимое в журнале. В production заданы `CRYPTOLAB_PUBLIC_ORIGIN` с
основным HTTPS-адресом и `CRYPTOLAB_COOKIE_SECURE=1`.

При переносе действующего стенда остановите старое приложение, получите
согласованный снимок SQLite и скопируйте **весь** каталог данных вместе с CA
и ключом серверного участника. Восстановите владельца `10001:10001`, права
каталогов `0700`, ключей и БД `0600`. Проверьте целостность SQLite и отпечаток CA.
**Не запускайте init поверх перенесённых данных.**

Только для совершенно нового независимого стенда с пустым `data/`:

```sh
cd /srv/course/lab06
docker compose run --rm --no-deps lab06 python -m app.ca init
docker compose run --rm --no-deps lab06 python -m app.service init
```

После восстановления или первоначальной инициализации:

```sh
cd /srv/course/lab06
docker compose config -q
docker compose up -d --wait lab06
docker compose exec -T lab06 python -m app.ca fingerprint
```

`Dockerfile` закрепляет digest Python 3.12, а `requirements-runtime.lock` —
ограничения версий из действующего окружения. При установке `pip -c` пакеты,
нужные только тестам, сами по себе не устанавливаются. Зависимости обновляются
отдельным проверенным изменением, а не при каждом пересоздании контейнера.

## Общий Caddy и HTTPS

Для нового ingress-проекта:

```sh
sudo install -d -m 750 -o "$(id -un)" -g "$(id -gn)" /srv/course/ingress/caddy
cp /srv/course/lab06/source/deploy/ivan/ingress/compose.yaml /srv/course/ingress/compose.yaml
cp /srv/course/lab06/source/deploy/ivan/ingress/Caddyfile /srv/course/ingress/caddy/Caddyfile
cd /srv/course/ingress
docker compose config -q
docker compose run --rm --no-deps caddy caddy validate --config /etc/caddy/Caddyfile
docker compose up -d
```

Шаблон ingress описывает текущую ЛР №6. Если Caddy уже обслуживает другие
стенды, добавляйте сеть и блок домена в существующие файлы, не заменяя их целиком.
Сеть лабораторной должна существовать до запуска ingress.

DNS основного имени должен указывать на сервер, порты 80/443 должны быть
доступны. Caddy сам получает и продлевает сертификаты. Его `/data` и `/config`
хранятся в постоянных Docker volumes; не удаляйте их через `down -v`.

Для изменения маршрутов отредактируйте хостовый Caddyfile, затем:

```sh
cd /srv/course/ingress
docker compose exec -T caddy caddy validate --config /etc/caddy/Caddyfile
docker compose exec -T caddy caddy reload --config /etc/caddy/Caddyfile
docker compose logs --tail=80 caddy
```

Каталог конфигурации внутри контейнера read-only. `reload` применяет Caddyfile
без остановки прокси. Изменение Compose или его сетей требует `up -d`.
`ivan.denrad.dev` перенаправляет на основной адрес ЛР №6.

UFW на ivan разрешает 22/tcp, 80/tcp, 443/tcp и 443/udp; прочие входящие
запрещены. Публикация контейнерных портов может обходить UFW, поэтому порт
приложения привязан к loopback. Fail2ban защищает SSH. Ключи студентов в
IndexedDB и cookie привязаны к origin — сохраняйте прежний HTTPS-домен.

## Обновление и диагностика

```sh
cd /srv/course/lab06
docker compose ps
docker compose logs --tail=80 lab06
curl -fsS http://127.0.0.1:18066/ -o /dev/null
```

Перед обновлением сделайте согласованную резервную копию, запишите текущие
commit SHA и image ID, сохраните образ под отдельным rollback-тегом.
Доставьте проверенный checkout нужного коммита в `source/`. После синхронизации
production-файлов через этот репозиторий checkout становится источником сборки;
не перезаписывайте исходники непроверенными ручными правками.

```sh
cd /srv/course/lab06
# Новый тег предотвращает перезапись предыдущего образа при сборке.
export CRYPTOLAB_IMAGE=course/cryptolab:release-YYYYMMDD-N
docker compose build lab06
docker compose up -d --wait lab06
```

Сохраните выбранный `CRYPTOLAB_IMAGE` в закрытом `/srv/course/lab06/.env`,
чтобы следующие команды Compose использовали тот же тег. Это переменная
интерполяции Compose; Telegram-переменные контейнера находятся в `runtime.env`.
Сам по себе `pull` не обновляет локально собираемый образ приложения.
После изменения runtime.env примените `up -d`: `restart` новые переменные
окружения не перечитывает. Используйте `docker compose config -q` для проверки
без печати секретов: полный вывод `config` может раскрыть env.

На момент переноса исходники на ivan были доставлены архивом без `.git`.
Для перехода к checkout сначала сохраните этот снимок вне `source/`, затем
замените только `source/` проверенным checkout. Соседние data/env не затрагивайте.

## Telegram через HTTP CONNECT proxy

На ivan используется `HTTPS_PROXY` из закрытого runtime.env; Python `urllib`
поддерживает HTTP CONNECT без SOCKS-библиотек. Укажите URL с URL-encoded
логином/паролем и `NO_PROXY=localhost,127.0.0.1`. При прямом доступе к Telegram
переменную прокси можно не задавать.

Текущая инфраструктурная зависимость:

```text
контейнер → 172.18.0.1:18080 на ivan
          → SSH reverse tunnel → 127.0.0.1:8000 на drum-lightrail
          → HTTP CONNECT 3proxy → Telegram
```

Сервис [ivan/telegram-tunnel.service](ivan/telegram-tunnel.service) установлен
на `drum-lightrail.exe.xyz` как `cryptolab-telegram-tunnel.service`. Он автоматически
переподключается. Private key и known_hosts находятся в `/etc/cryptolab-tunnel/`
на drum и в репозитории отсутствуют. Сервис зависит от существующего 3proxy
с авторизацией и разрешением только `*telegram.org:443`.

На ivan отдельный пользователь `tg-tunnel` имеет ограниченный ключ и SSH
настройки: `GatewayPorts clientspecified`, `AllowTcpForwarding remote`,
`PermitListen 172.18.0.1:18080`, без shell/TTY/agent forwarding. UFW разрешает
этот listener только из `172.18.0.0/16` к `172.18.0.1`. Если Docker-сеть
пересоздаётся с другим gateway, согласованно измените tunnel, ограничения SSH,
правило firewall и HTTPS_PROXY. Прокси не должен слушать публичный интерфейс.

```sh
ssh drum-lightrail.exe.xyz 'sudo systemctl status cryptolab-telegram-tunnel --no-pager'
ssh drum-lightrail.exe.xyz 'sudo journalctl -u cryptolab-telegram-tunnel -n 50 --no-pager'
```

Уведомление сообщает факт записи сдачи. Ошибка Telegram не отменяет запись;
повторная отправка сдачи повторяет уведомление, если успех ещё не подтверждён.
Для диагностики API используйте getMe без отправки тестовых студенческих сдач
на production. Никогда не выводите токен или URL с паролем в журнал.

## Резервное копирование и откат

SQLite работает в WAL. Простое копирование одного live-файла может потерять
последние изменения. Используйте SQLite backup API либо остановите приложение
и архивируйте весь `data/`. Пример с короткой остановкой, на ivan:

```sh
(
set -e
cd /srv/course/lab06
stamp=$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 700 /srv/course/backups
docker compose stop lab06
trap 'docker compose start lab06' EXIT
sudo sh -c 'umask 077; tar -czf "$1" -C /srv/course/lab06 data runtime.env compose.yaml telegram.production.env' sh "/srv/course/backups/lab06-$stamp.tar.gz"
)
```

`telegram.production.env` — сохранённая во время миграции исходная конфигурация;
на новом стенде, где её нет, исключите этот файл из команды. Если задан отдельный
`.env` с тегом образа, также сохраните его. Архив root-only содержит секреты
и персональные данные: храните вне Git и публичных каталогов.
Trap запускает приложение при завершении блока, в том числе при ошибке.
Регулярный backup и копирование вне сервера требуют отдельной настройки.

Для восстановления остановите запись, сохраните текущие данные отдельно,
восстановите data и секреты с правильными UID/GID и правами, запустите Compose.
Проверьте `PRAGMA integrity_check`, число сдач, CA fingerprint и HTTPS.
Для восстановления всего сервера дополнительно нужны версия исходников,
ingress-конфигурация, volumes Caddy и доступный Telegram-прокси.

Для отката к предыдущему коду используйте сохранённый image ID/tag и
совместимые актуальные данные. Для возврата на exe.dev сначала перенесите туда
самую свежую БД и ключи, затем верните DNS и включите старый сервис. Просто
включить старую копию после новых сдач на ivan означает потерять эти сдачи.

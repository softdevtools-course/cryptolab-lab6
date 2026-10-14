# Публичный учебный стенд на exe.dev

Студенческий адрес: <https://lab-06.course.denrad.dev/>. Веб-прокси VM
`cryptolab-lab6` открыт для всех; учётная запись exe.dev студентам не нужна.
HTTPS завершает прокси exe.dev. Приложение слушает только `127.0.0.1:8000`.
Публичный доступ к веб-странице не даёт доступ к VM или SSH.

На странице студент вводит фамилию, имя и группу. Это самозаявленные данные,
а не подтверждение личности; преподаватель сверяет результат отдельно.
Приложение проверяет `Origin` изменяющих запросов, ограничивает их размер и
частоту запросов и создания новых сеансов. Для этих проверок в сервисе задано
`CRYPTOLAB_PUBLIC_ORIGIN=https://lab-06.course.denrad.dev`.

Код: `/opt/cryptolab/current/`. Постоянные данные: `/var/lib/cryptolab/`.
В последнем каталоге находятся CA, отдельный ключ серверного участника и SQLite.
Каталог, ключи, БД и резервные копии не должны попадать в Git или в публикуемые
сборки. Перед открытием веб-прокси создана резервная копия
`/var/lib/cryptolab/backups/pre-public-2026-10-14.tar.gz`; её копия хранится
локально в игнорируемой Git папке `.local-data/backups/`. Восстановление
проверено на копии: целостность SQLite и соответствие ключей сертификатам.

Управление сервисом:

```bash
ssh cryptolab-lab6.exe.xyz 'sudo systemctl status cryptolab --no-pager'
ssh cryptolab-lab6.exe.xyz 'sudo journalctl -u cryptolab -n 80 --no-pager'
ssh exe.dev share show cryptolab-lab6
ssh exe.dev share set-private cryptolab-lab6
ssh exe.dev share set-public cryptolab-lab6
```

Контрольный отпечаток CA получают на VM:

```bash
ssh cryptolab-lab6.exe.xyz 'cd /opt/cryptolab/current && CRYPTOLAB_DATA_DIR=/var/lib/cryptolab .venv/bin/python -m app.ca fingerprint'
```

Общедоступный стенд не устанавливает личность студента. Его фамилия, имя и
группа помогают сверить запись сдачи; окончательное решение принимает
преподаватель. Учебные закрытые ключи из `examples/` публичны намеренно и не
используются как ключи CA или серверного участника.

# Приватный стенд на exe.dev

Приложение размещено на VM `cryptolab-lab6` как приватный тестовый стенд.
HTTPS завершает прокси exe.dev; приложение слушает только `127.0.0.1:8000`.
Не переводите proxy в режим public без отдельной проверки безопасности и
привязки учебной записи к студенту.

Код: `/opt/cryptolab/current/`. Постоянные данные: `/var/lib/cryptolab/`.
В последнем каталоге находятся CA, отдельный ключ серверного участника и SQLite.
Каталог, ключи и БД не должны попадать в Git или в публикуемые сборки.

Управление сервисом:

```bash
ssh cryptolab-lab6.exe.xyz 'sudo systemctl status cryptolab --no-pager'
ssh cryptolab-lab6.exe.xyz 'sudo journalctl -u cryptolab -n 80 --no-pager'
```

Контрольный отпечаток CA получают на VM:

```bash
ssh cryptolab-lab6.exe.xyz 'cd /opt/cryptolab/current && CRYPTOLAB_DATA_DIR=/var/lib/cryptolab .venv/bin/python -m app.ca fingerprint'
```

Серверный секрет и пароль в приложении не используются: доступ к превью
ограничен приватным прокси exe.dev. `Secure` cookie включён; для внешнего
студенческого пилота ещё нужны идентификация, CSRF-защита, ограничения частоты,
резервное копирование и процедура восстановления доступа.

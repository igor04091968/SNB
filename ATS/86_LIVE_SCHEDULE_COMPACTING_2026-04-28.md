# Дефектовка расписаний: компактная миграция (live)

Дата: 2026-04-28  
Хост применения: `asterisk_test` (`10.33.1.82`)  
Целевой файл на АТС: `/etc/asterisk/extensions_custom.lua`

## Что изменено

1. Номера `409597`, `441219`, `445957`:
- Вынесена общая логика в компактный helper `upk_is_afterhours()`.
- Убраны длинные повторяющиеся списки по каждому номеру.
- Введен единый обработчик `upk_handle_call(queue_name, ext_label)`.

2. Номер `409703`:
- Логика расписаний приведена к компактному виду через `ExecIfTime` с человеко-читаемыми группами:
- `AOP_NY`: `1-11 Jan`, `31 Dec`
- `AOP_DAY_OFF`: праздники + `Sat-Sun` + `17:30-08:30 Mon-Fri`
- `AOP_OFF118`: предпраздничные окна + `16:45-08:30 Mon-Thu` и `16:30-08:30 Fri`

## Применение вживую

1. Проверка локального Lua:
```bash
luac -p /home/igor/SNB/ATS/extensions_custom.lua.new_ats.remote
```

2. Загрузка файла на тестовую АТС:
```bash
ssh-upload /tmp/extensions_custom.lua.new_ats.remote
```

3. Резервная копия live-файла:
```bash
cp /etc/asterisk/extensions_custom.lua \
   /etc/asterisk/extensions_custom.lua.bak_YYYYmmdd_HHMMSS_compact_409703
```

4. Установка нового файла:
```bash
cp /tmp/extensions_custom.lua.new_ats.remote /etc/asterisk/extensions_custom.lua
```

5. Проверка синтаксиса на АТС:
```bash
luac -p /etc/asterisk/extensions_custom.lua
```

6. Перезагрузка Lua-диалплана:
```bash
asterisk -rx "module reload pbx_lua.so"
```

## Фактический бэкап этого прогона

`/etc/asterisk/extensions_custom.lua.bak_20260428_134649_compact_409703`


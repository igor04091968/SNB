# SNB Locations Feed

Небольшой автономный проект для подготовки фида по адресам банкоматов и офисов Северного Народного Банка на основе живых данных с `sevnb.ru`.

## Что делает

- забирает данные с `https://www.sevnb.ru/searchcity/json`;
- забирает данные с `https://www.sevnb.ru/searchoffices/json`;
- нормализует адреса, телефоны и режимы работы;
- собирает единый фид в `JSON`, `CSV` и `XML`.

## Запуск

```bash
cd snb-locations-feed
python3 feed_builder.py
```

Файлы появятся в каталоге `dist/`:

- `sevnb_locations.json`
- `sevnb_locations.csv`
- `sevnb_locations.xml`
- `summary.json`

Можно вывести результат сразу в stdout:

```bash
python3 feed_builder.py --stdout json
python3 feed_builder.py --stdout csv
python3 feed_builder.py --stdout xml
```

## Источник данных

- Банкоматы: `https://www.sevnb.ru/atms`
- Офисы: `https://www.sevnb.ru/offices`
- JSON API, используемое сайтом:
  - `https://www.sevnb.ru/searchcity/json?city=Сыктывкар`
  - `https://www.sevnb.ru/searchoffices/json?city=Сыктывкар`

## Проверка

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

# surface — Android attack surface mapper for Termux

**Без root. Без adb. Прямо на телефоне.**

`surface` читает установленные APK, разбирает `AndroidManifest.xml` и показывает, какие «двери» приложения открыты наружу: экспортированные activity/service/receiver/provider, deep links, разрешения и опасные комбинации.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square)
![Termux](https://img.shields.io/badge/Termux-no%20root-black?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-bd2940?style=flat-square)

## Зачем

На Android у каждого приложения есть компоненты, к которым могут обращаться другие программы. Если разработчик оставил их открытыми, чужие приложения могут читать данные или запускать код. `surface` находит такие места и считает риск — без компьютера и без прав root.

## Установка

```bash
pkg install python
git clone https://github.com/Xnode-sh/surface.git
cd surface
python surface.py list
```

Зависимостей нет — только стандартная библиотека Python.

## Использование

```bash
# список установленных пакетов
python surface.py list

# карта поверхности одного приложения, с деталями
python surface.py scan -p com.android.chrome -v

# все приложения + отчёты
python surface.py scan --json report.json --md report.md

# только то, что выше порога риска
python surface.py scan --min-score 10
```

Вывод:

```
SCORE   H  M  L  PACKAGE
  388   5 77 30  app.example.photos
   44   3  1 10  android
```

`H/M/L` — число находок high/medium/low, `SCORE` — их взвешенная сумма.

## Что проверяется

| Правило | Severity |
|---|---|
| `debuggable=true` | high |
| Экспортированный `provider` без permission | high |
| Экспортированный `service`/`receiver` без permission | medium |
| Browsable deep link (VIEW + BROWSABLE) | medium |
| `allowBackup=true` | medium |
| Экспортированная `activity` без permission | low |
| `targetSdk < 30` | low |
| Опасные разрешения | info |

## Ограничения

- Анализ только по манифесту: без декомпиляции кода.
- `exported` без явного значения выводится по правилам платформы.
- Часть системных APK может быть недоступна для чтения — такие пакеты помечаются `error`.

## Лицензия

MIT © 2026 Xnode-sh — RED └•TEAM•┐ lab™

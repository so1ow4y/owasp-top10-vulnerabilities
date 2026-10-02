# Python/Flake8

**WeBob** - библиотека для работы с HTTP-запросами и ответами в Python. Предоставляет объекты-обертки для WSGI-окружения, упрощающие парсинг запросов и формирование ответов.

**Ссылка на репозиторий:**

**https://github.com/Pylons/webob**

**Полная версия отчёта доступна по ссылке:**

**https://gitlab.com/ere6u5/linter-secure-audit/-/blob/main/README.md?ref_type=heads&plain=1**

## Чек-лист из файла [`webob.summary`](https://gitlab.com/ere6u5/linter-secure-audit/-/blob/main/projects/python/webob.summary?ref_type=heads)

| Категория                | Количество  | Уязвимости                          |
|--------------------------|-------------|-------------------------------------|
| **Безопасность**         | 2573        |`S101`, `S603`, `S108`, `S324`, `S607`, `S404`, `S311`|
| **Документация**         | 2207        |`D102`, `D103`, `D400`, `D202`, `D101`, `D105`, `D200`, `D205`, `D100`, `D107`, `D401`, `D209`, `D412`, `D301`, `D403`, `D104`|
| **Потенциальные ошибки** | 53          |`B028`,`B010`,`B015`,`B009`,`B036`,`B023`       |
| **Прочие**               | 30          |...                                |
| **Всего**                | 4863        |


## Топ-3 security-проблемы

### S101: Небезопасное использование `assert` для валидации (Production)

**Уязвимый код:**

- [`response.py:1569-1570:1`](./projects/python/webob/src/webob/response.py)
```python
def __init__(self, app_iter, start, stop):
    assert start >= 0, "Bad start: %r" % start
    assert stop is None or (stop >= 0 and stop >= start), "Bad stop: %r" % stop
```

- [`response.py:1594:1`](./projects/python/webob/src/webob/response.py)
```python
if stop is not None and self._pos > stop:
    chunk = chunk[: stop - self._pos]
    assert len(chunk) == stop - start
```

**Суть проблемы:**
- Использование `assert` для проверки входных параметров и условий в production
- При использования флага оптимизации - проверки `assert` будут опущены
- Проблема обнаружена в основном коде(не в тестах)

**Оценка риска**
- Высокий (для production кода с флагом `python -O`)

**Потенциальные проблемы:**
- Критичные ошибки в работе приложения
- Невалидные данные могут пройти проверку

**Рекомендации по исправлению**
- Использование инструкции `raise` вместо `assert`. Например:
```python
if start < 0:
    raise ValueError(f"Invalid start value: {start}")
```

**Ссылки**

- [CWE-617: Reachable Assertion](https://cwe.mitre.org/data/definitions/617.html)

---
### S603: Выполнение произвольных команд (Testing)

**Уязвимый код:**

- [`perfomance_test.py:37:1`](./projects/python/webob/tests/performance_test.py)
```python
proc = subprocess.Popen([sys.executable, __file__]) # Исполнение текущего файла
```

- [`performance_test.py:39:1`](./projects/python/webob/tests/performance_test.py)
```python
subprocess.call(["ab", "-n", "1000", "http://localhost:8080/"]) # вызов внешней утилиты
```

**Суть проблемы:**
- Прямой вызов субпроцессов с динамическими параметрами

**Оценка риска:**
- Низкий (используется в тестовом окружении)

**Потенциальные проблемы:**
- Отсутствие обработки ошибок при отсутствии `ab` в системе

**Потенциальные последствия:**
- Исполнение произвольного кода (RCE) в тестовом окружении через подмену `__file__`

**Рекомендация:**
- Использовать Whitelist для разрешенных команд
- Заменить код на чистый Python. Если в окружении нет явного `ab` - возможны ошибки.

**Ссылки**
- [CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')](https://cwe.mitre.org/data/definitions/78.html)

---
### S108: Небезопасная работа с временными файлами (Testing)

**Уязвимый код:**

- [`perfomance_test.py:10:1`](./projects/python/webob/tests/performance_test.py)
```python
log_filename="/tmp/profile.log",
```

- [`test_static.py:62:1`](./projects/python/webob/tests/test_static.py)
```python
app = static.FileApp("/tmp/this/doesnt/exist")
```

**Суть проблемы:**
- Использование фиксированных путей `/tmp` без контроля

**Оценка риска:**
- Низкий (используется тестовое окружение)

**Потенциальные проблемы:**
- Утечка данных между тестами

**Потенциальные последствия:**
- Перезапись файлов при параллельном запуске тестов

**Рекомендация:**
- Исправить в рамках рефакторинга

**Ссылки**
- [CWE-377: Insecure Temporary File](https://cwe.mitre.org/data/definitions/377.html)

---
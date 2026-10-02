# JavaScript/ESLint

**Eve** - JavaScript библиотека для визуализации данных с использованием D3.js. Предоставляет компоненты для построения сложных интерактивных диаграмм и карт.

**Ссылка на репозиторий:**

**https://github.com/ozdemiri/eve**

**Полная версия отчёта доступна по ссылке:**

**https://gitlab.com/ere6u5/linter-secure-audit/-/blob/main/README.md?ref_type=heads&plain=1**


## Чек-лист из файла [`eve.summary`](https://gitlab.com/ere6u5/linter-secure-audit/-/blob/main/projects/javascript/eve.summary?ref_type=heads)

| Категория                | Количество | Уязвимости |
|--------------------------|------------|------------|
| **Critical Security**    | 1216       | Object Injection, Code Injection, Hardcoded Secrets |
| **High Risk Issues**     | 831        | Undefined Variables, Unsafe Operations |
| **Code Quality**        | 359        | Unused Variables |
| **Best Practices**      | 34         | Promise Handling |
| **Other Issues**        | 1347       | Undefined globals, Prototype access |
| **Всего**               | 3633       |            |


## Топ-3 security-проблемы

### Non-literal Resource

**Уязвимый код**

- [`eve.js:883:21`](./projects/javascript/eve/src/eve.js)
```javascript
name = name.replace(/[\[]/, "\\\[").replace(/[\]]/, "\\\]");
let regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
```

**Суть проблемы**
1. **Использование регулярных выражений на основе ввода:**
    - Если `name` содержит специальные символы для `RegExp`, это может сломать логику проверки или привести к ReDoS (Regular Expression Denial of Service), если злоумышленник передаст какой-либо сложный паттерн

**Риски**
| Угроза               | Уровень  | Последствия                                                                 |
|----------------------|----------|-----------------------------------------------------------------------------|
| **ReDoS**            | Высокий  | Увеличение нагрузки на CPU (отказ в обслуживании)                          |
| **Логическая ошибка** | Средний  | Некорректное извлечение параметров                                  |
| **Инъекция**         | Низкий   | В редких случаях — выполнение произвольного кода через сложные регулярки   |

**Рекомендации**

1. Использовать экранирование символов, если `name` - внешний параметр
```javascript
function escapeRegExp(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

const safeName = escapeRegExp(name);
const regex = new RegExp("[\\?&]" + safeName + "=([^&#]*)");
```

2. Использовать заранее разрешённые параметры для `name`:
```javascript
const ALLOWED_PARAMS = ['id', 'name', 'page'];
if (!ALLOWED_PARAMS.includes(name)) throw new Error('Invalid param');

const regex = new RegExp(`[\\?&]${name}=([^&#]*)`);
```

**Ссылки**

- [CWE-185: Incorrect Regular Expression](https://cwe.mitre.org/data/definitions/185.html)

---

### Code Injection

**Уязвимый код**

- [`eve.js:853:17`](./projects/javascript/eve/src/eve.js)
```javascript
eval('sub.' + key1 + ' = base.' + key1);
```

**Суть проблемы**  
1. **Динамическое выполнение кода через `eval`**  
   - Позволяет выполнить произвольный JavaScript-код при контроле над `key1`

2. **Возможность инъекции кода**  
   - Если атакующий может контролировать свойства объекта `base`, он может:
     - Внедрить вредоносный JavaScript-код
     - Выполнить произвольные операции в контексте приложения

**Оценка риска**
| Риск                | Уровень  | Обоснование                                                                 |
|---------------------|----------|-----------------------------------------------------------------------------|
| Инъекция кода       | Критический | Может привести к полному компрометированию приложения (RCE)               |
| Утечка данных       | Высокий  | Позволяет получить доступ к чувствительной информации в контексте         |
| Нарушение работы    | Высокий  | Может привести к изменению логики работы приложения                       |

**Рекомендации**

1. **Избегать использования `eval`:** Заменить на безопасные альтернативы
2. **Использовать строгий режим:** Добавить `'use strict'` для ограничения контекста `eval`

**Ссылки**
- [CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

---

### Hardcoded Secret

**Уязвимый код**

В трёх местах обнаружены захардкоженные API ключи, seed для генерации и закоментированная юрла.

- [`eve.js:146:20`](./projects/javascript/eve/src/eve.js)
```javascript
vectorKey: "TiNL5etp1GifX4gsKGzS"
```
- [`eve.js:739:21`](./projects/javascript/eve/src/eve.js)
```javascript
eve.randColor = function () {
    let chars = '0123456789ABCDEF'.split(''),
        color = '#';

    for (let i = 0; i < 6; i++)
        color += chars[Math.floor(Math.random() * 16)];

    return eve.hexToRgbString(color);
};
```

- [`eve.vectortileconverter.js:1709:1`](./projects/javascript/eve/src/maps/eve.vectortileconverter.js)
```javascript
//# sourceMappingURL=Leaflet.VectorGrid.bundled.js.map
```

**Суть проблемы**  
1. **API-ключ MapTiler**  
   - Ключ `TiNL5etp1GifX4gsKGzS` жёстко закодирован в коде, что позволяет:
     - Получить доступ к платным возможностям сервиса.

2. **Псевдослучайная генерация цвета**  
   - Фиксированный набор символов (`0123456789ABCDEF`) снижает энтропию генерации.

3. **Раскрытие структуры проекта**  
   - Закомментированный путь к sourcemap-файлу может раскрыть внутреннюю структуру файлов.

**Оценка риска**
| Риск                | Уровень  | Обоснование                                                                 |
|---------------------|----------|-----------------------------------------------------------------------------|
| Утечка API-ключа    | Высокий  | Может привести к финансовым потерям и злоупотреблению сервисом.            |
| Слабая генерация    | Низкий   | Не влияет на безопасность.     |
| Раскрытие структуры | Средний  | Может упростить анализ кода для атакующего.                                |

**Рекомендации**
1. Для API ключа использовать переменные окружения.
2. Для генерации цвета использовать `crypto` библиотеки.
3. Для комментария - удалить перед продакшеном.

**Ссылки**
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

---
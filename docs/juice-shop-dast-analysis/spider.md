# Отчет по анализу уязвимостей с помощью OWASP ZAP - Spider и Spider-AJAX

**Полная версия отчёта доступна по ссылке:**

**https://gitlab.com/ere6u5/juice-shop-dast-analysis**

## Отсутствие заголовка Content Security Policy (CSP)

### Обнаруженные инстансы

ZAP обнаружил 147 экземпляров отсутствия CSP на различных URL, включая:
- Главную страницу (`http://localhost:3000/`)
- FTP-ресурсы (`http://localhost:3000/ftp/*`)
- Статические ресурсы (`http://localhost:3000/assets/public/*`)
- API-эндпоинты (`http://localhost:3000/juice-shop/*`)

### Суть проблемы

**1. Отсутствие защиты CSP:**
- Веб-приложение не использует заголовок Content Security Policy
- Это позволяет выполнять потенциально опасные действия, такие как:
  - Загрузка скриптов с внешних доменов
  - Внедрение inline-скриптов
  - Загрузка ресурсов с непроверенных источников

**2. Потенциальные риски:**
- Cross-Site Scripting (XSS) атаки
- Внедрение вредоносного кода
- Загрузка поддельных ресурсов

### Оценка риска

| Риск | Уровень | Обоснование |
|------|---------|-------------|
| XSS-атаки | Высокий | Без CSP приложение уязвимо к внедрению скриптов |
| Data Injection | Средний | Возможность подмены загружаемых ресурсов |
| Clickjacking | Средний | Отсутствие ограничений на фреймы |

### Рекомендации

1. **Добавить CSP заголовок:**
```http
Content-Security-Policy: default-src 'self'
```

2. **Реализовать в Express.js:**
```javascript
app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  next();
});
```


### Ссылки

**CWE:**  
- [CWE-693: Protection Mechanism Failure](https://cwe.mitre.org/data/definitions/693.html)

**OWASP Top 10:**  
- [A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

## Неправильная конфигурация CORS

### Обнаруженные инстансы

ZAP обнаружил 161 экземпляр проблемной конфигурации CORS:
- Все ответы содержат `Access-Control-Allow-Origin: *`
- Затронуты те же URL, что и в случае с CSP

### Суть проблемы

**1. Излишне разрешительная политика CORS:**
- Сервер разрешает запросы с любых доменов (`*`)
- Это включает потенциально вредоносные сайты

**2. Потенциальные риски:**
- Утечка данных через межсайтовые запросы
- CSRF-атаки
- Доступ к API с непроверенных источников

### Оценка риска

| Риск | Уровень | Обоснование |
|------|---------|-------------|
| Утечка данных | Высокий | Возможность чтения данных через API |
| CSRF | Средний | Упрощение проведения атак |
| Злоупотребление API | Средний | Неограниченный доступ к API |

### Рекомендации

1. **Ограничить разрешенные домены:**
```http
Access-Control-Allow-Origin: https://trusted-domain.com
```

2. **Реализовать в Express.js:**
```javascript
const corsOptions = {
  origin: 'https://trusted-domain.com',
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));
```

3. **Для публичных API:**
- Использовать валидацию Origin
- Ограничить методы HTTP
- Добавить заголовки CORS только для необходимых путей

### Ссылки

**CWE:**  
- [CWE-264: Permissions, Privileges, and Access Controls](https://cwe.mitre.org/data/definitions/264.html)

**OWASP Top 10:**  
- [A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

## Обнаружение скрытых файлов

### Обнаруженные инстансы

ZAP обнаружил доступ к скрытым файлам:
- `http://localhost:3000/._darcs`
- `http://localhost:3000/.bzr`
- `http://localhost:3000/.hg`
- `http://localhost:3000/BitKeeper`

### Суть проблемы

**1. Доступ к системным файлам:**
- Веб-сервер раскрывает файлы систем контроля версий
- Может содержать конфиденциальную информацию:
  - История изменений
  - Имена пользователей
  - Внутренние пути

**2. Потенциальные риски:**
- Раскрытие структуры проекта
- Утечка метаданных
- Возможность найти дополнительные уязвимости

### Оценка риска

| Риск | Уровень | Обоснование |
|------|---------|-------------|
| Утечка информации | Средний | Раскрытие внутренней структуры |
| Увеличение поверхности атаки | Средний | Возможность найти другие уязвимости |

### Рекомендации

1. **Запретить доступ к скрытым файлам:**
```nginx
location ~ /\. {
  deny all;
  return 404;
}
```

2. **Для Express.js:**
```javascript
app.get('/\.*', (req, res) => {
  res.status(404).send('Not found');
});
```

3. **Дополнительные меры:**
- Регулярно проверять наличие лишних файлов
- Использовать `.gitignore` и аналоги
- Настроить веб-сервер на запрет доступа к служебным каталогам

### Ссылки

**CWE:**  
- [CWE-538: File and Directory Information Exposure](https://cwe.mitre.org/data/definitions/538.html)

**OWASP Top 10:**  
- [A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

## Включение JavaScript из сторонних доменов

### Обнаруженные инстансы

ZAP обнаружил 15 случаев включения JS из cdnjs.cloudflare.com:
- `//cdnjs.cloudflare.com/ajax/libs/cookieconsent2/3.1.0/cookieconsent.min.js`
- `//cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js`

### Суть проблемы

**1. Зависимость от сторонних ресурсов:**
- Скрипты загружаются с внешнего CDN
- Нет контроля целостности (отсутствует SRI)
- Возможность подмены скриптов

**2. Потенциальные риски:**
- XSS через подмену скриптов
- Нарушение работы приложения при недоступности CDN
- Отслеживание пользователей

### Оценка риска

| Риск | Уровень | Обоснование |
|------|---------|-------------|
| Подмена скриптов | Средний | Возможность внедрения вредоносного кода |
| Нарушение доступности | Низкий | Зависимость от внешнего сервиса |

### Рекомендации

1. **Использовать Subresource Integrity (SRI):**
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/2.2.4/jquery.min.js" 
        integrity="sha384-..." 
        crossorigin="anonymous"></script>
```

2. **Локальное хранение зависимостей:**
- Загрузить скрипты в проект
- Обслуживать со своего сервера

3. **Регулярно обновлять зависимости:**
- Следить за обновлениями на CDN
- Обновлять хеши SRI

### Ссылки

**CWE:**  
- [CWE-829: Inclusion of Functionality from Untrusted Control Sphere](https://cwe.mitre.org/data/definitions/829.html)

**OWASP Top 10:**  
- [A06:2021 - Vulnerable and Outdated Components](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/)

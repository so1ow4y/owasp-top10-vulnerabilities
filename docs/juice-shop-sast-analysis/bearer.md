# Отчет по анализу уязвимостей с помощью Bearer


**Полная версия отчёта доступна по ссылке:**

**https://gitlab.com/ere6u5/juice-shop-sast-analysis**

## SQL Injection и Timing Attack в модуле аутентификации

### Уязвимый код

#### Обнаружены сканером:

1. **SQL Injection**:
- [`juice-shop/routes/login.ts:34`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/routes/login.ts)
```typescript
models.sequelize.query(`SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`, { model: UserModel, plain: true })
```

2. **Timing Attack**:
- [`juice-shop/routes/login.ts:37`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/routes/login.ts)
```typescript
if (user.data?.id && user.data.totpSecret !== '')
```

### Суть проблемы

**1. SQL Injection:**
- Прямая конкатенация пользовательского ввода (email и password) в SQL-запрос
- Отсутствие параметризации или санитизации входных данных
- Возможность выполнения произвольных SQL-команд

**2. Timing Attack:**
- Небезопасное сравнение TOTP секрета
- Разное время выполнения для существующих и несуществующих пользователей
- Возможность перебора валидных пользователей по времени ответа

### Оценка риска

| Уязвимость          | Уровень риска | Обоснование |
|---------------------|---------------|-------------|
| SQL Injection       | Критический   | Позволяет обойти аутентификацию, читать/модифицировать данные |
| Timing Attack       | Высокий       | Позволяет перебрать валидных пользователей |
| Компрометация данных | Высокий      | Возможность доступа к конфиденциальной информации |

#### True/False Positive:
- SQL Injection: **True Positive** (явная конкатенация в запросе)
- Timing Attack: **True Positive** (небезопасное сравнение строк)

### Рекомендации

**Для SQL Injection:**
1. Использовать параметризованные запросы:
```typescript
models.sequelize.query(
  "SELECT * FROM Users WHERE email = ? AND password = ? AND deletedAt IS NULL",
  { 
    replacements: [req.body.email, security.hash(req.body.password)],
  }
)
```

**Для Timing Attack:**
1. Использовать безопасное сравнение:
```typescript
import { timingSafeEqual } from 'crypto'

function safeCompare(a: string, b: string) {
  try {
    return timingSafeEqual(Buffer.from(a), Buffer.from(b))
  } catch {
    return false
  }
}

if (user.data?.id && !safeCompare(user.data.totpSecret, ''))
```

2. Добавить искусственную задержку:
```typescript
await new Promise(resolve => setTimeout(resolve, 200))
```

### Ссылки

**CWE:**
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [CWE-208: Observable Timing Discrepancy](https://cwe.mitre.org/data/definitions/208.html)

**OWASP Top 10:**
- [A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)
- [A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

## Утечка информации через логи

### Уязвимый код

#### Обнаружены сканером:

- [`juice-shop/frontend/src/app/purchase-basket/purchase-basket.component.ts:51`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/frontend/src/app/purchase-basket/purchase-basket.component.ts)
```typescript
}, (err) => { console.log(err) })
```

- [`juice-shop/frontend/src/app/purchase-basket/purchase-basket.component.ts:67`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/frontend/src/app/purchase-basket/purchase-basket.component.ts)
```typescript
}, (err) => { console.log(err) })
```

- [`juice-shop/frontend/src/app/purchase-basket/purchase-basket.component.ts:74`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/frontend/src/app/purchase-basket/purchase-basket.component.ts)
```typescript
}, (err) => { console.log(err) })
```

- [`juice-shop/frontend/src/app/purchase-basket/purchase-basket.component.ts:94`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/frontend/src/app/purchase-basket/purchase-basket.component.ts)
```typescript
console.log(err)
```

- [`juice-shop/frontend/src/app/purchase-basket/purchase-basket.component.ts:96`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/frontend/src/app/purchase-basket/purchase-basket.component.ts)
```typescript
}, (err) => { console.log(err) })
```

### Суть проблемы

**1. Утечка информации через логи:**
- В коде обнаружено прямое логирование объектов ошибок (`err`) без фильтрации
- В ошибках могут содержаться `sensitive-data` (системная информация)

**2. Небезопасные практики логирования:**
- Использование `console.log` в продакшн-коде
- Отсутствие санитизации данных перед логированием
- Потенциальное раскрытие внутренней структуры приложения

### Оценка риска

| Риск                 | Уровень  | Обоснование |
|----------------------|----------|-------------|
| Раскрытие чувствительной информации | Средний | Зависит от содержимого ошибок |
| Компрометация системы | Низкий | Через логи может раскрыться внутренняя архитектура |
| Нарушение конфиденциальности | Средний | Возможность утечки PII или системных данных |

#### True/False Positive:
- **True Positive**: Уязвимость реальна, но риск зависит от содержимого ошибок

### Рекомендации

1. **Использовать структурированное логирование:**
```typescript
import { Logger } from 'winston';

private logger = new Logger();

this.logger.error('Operation failed', { 
  error: err.message, 
  code: err.code 
});
```

2. **Фильтровать чувствительные данные:**
```typescript
function sanitizeError(err: any) {
  return {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
  };
}

console.error(sanitizeError(err));
```

3. **Для продакшн-окружения:**
- Настроить уровни логирования
- Регулярно проверять логи на наличие `sensitive-data`

### Ссылки

**CWE:**
- [CWE-532: Information Exposure Through Log Files](https://cwe.mitre.org/data/definitions/532.html)

**OWASP Top 10:**
- [A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [A09:2021 - Security Logging and Monitoring Failures](https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/)

---
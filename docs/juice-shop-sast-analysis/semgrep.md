# Отчет по анализу уязвимостей с помощью Semgrep 

**Полная версия отчёта доступна по ссылке:**

**https://gitlab.com/ere6u5/juice-shop-sast-analysis**

## Harcoded JWT Secret и HMAC Key

### Уязвимый код

#### Обнаружены сканером:

- [`juice-shop/lib/insecurity.ts:44:39`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/lib/insecurity.ts)
```typescript
export const hmac = (data: string) => crypto.createHmac('sha256', 'pa4qacea4VK9t9nGv7yZtwmj').update(data).digest('hex')
```

- [`juice-shop/lib/insecurity.ts:23,56`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/lib/insecurity.ts)
```typescript
const privateKey = '-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----'
...
export const authorize = (user = {}) => jwt.sign(user, privateKey, { expiresIn: '6h', algorithm: 'RS256' })
```

- [`juice-shop/lib/insecurity.ts:152:16`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/lib/insecurity.ts)
```typescript
const hmac = crypto.createHmac('sha256', privateKey)
```

#### Обнаружено при ручной проверке:

- [`juice-shop/lib/insecurity.ts:43`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/lib/insecurity.ts)
```typescript
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
```

### Суть проблемы

**1. Жестко закодированные секретные ключи:**

- В коде обнаружены жестко закодированные криптографические ключи (HMAC и JWT private key).

**2. Использование устаревших алгоритмов**

- В функции `hash()` используется устаревший алгоритм MD5, который считается криптографически небезопасным.

### Оценка риска

| Риск                 | Уровень  | Обоснование |
|----------------------|----------|-------------|
| Раскрытие секретных ключей | Высокий | Жестко закодированные ключи могут быть извлечены из кода злоумышленниками |
| Подделка JWT токенов | Высокий | Доступ к приватному ключу позволяет злоумышленнику генерировать валидные токены |
| Уязвимости криптографии | Средний | Использование MD5 и жестко закодированных HMAC ключей снижает безопасность |

#### True/False Positive

- Все найденные уязвимости являются True Positive, так как действительно присутствуют в коде.

### Рекомендации

1. **Секретные ключи**:
   - Хранить ключи в переменных окружения, например в файлах `.env`.

2. **Для JWT**:
   ```typescript
   const privateKey = process.env.JWT_PRIVATE_KEY
   ```

3. **Для HMAC**:
   ```typescript
   export const hmac = (data: string) => 
     crypto.createHmac('sha256', process.env.HMAC_SECRET).update(data).digest('hex')
   ```

4. **Для хеширования**:
   - Заменить MD5 на более безопасный алгоритм, например на SHA-256

### Ссылки

**CWE:**
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

**OWASP Top 10:**
- [A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)


## XSS через insecure innerHTML

### Уязвимый код

#### Обнаружены сканером:

- [`juice-shop/frontend/src/hacking-instructor/index.ts:122`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/frontend/src/hacking-instructor/index.ts)
```typescript
textBox.innerHTML = snarkdown(hint.text)
```

### Суть проблемы

**1. Небезопасное использование innerHTML:**
- Прямое присваивание пользовательского ввода (`hint.text`) свойству `innerHTML` после преобразования Markdown-to-HTML.
- Библиотека `snarkdown` не обеспечивает полной санитизации HTML, оставляя возможность XSS-атак.

**2. Потенциальные векторы атаки:**
- Если злоумышленник может контролировать содержимое (например, через внедрение в файлы переводов или базу данных), он сможет внедрить произвольный JavaScript-код.

### Оценка риска

| Риск                 | Уровень  | Обоснование |
|----------------------|----------|-------------|
| Stored XSS           | Средний  | Зависит от возможности внедрения вредоносных подсказок |
| DOM-based XSS        | Средний  | Выполнение кода в контексте страницы Juice Shop |
| Компрометация сессии | Высокий  | Возможность кражи cookies или токенов аутентификации |

#### True/False Positive:
- **True Positive**: Уязвимость реальна, но риск снижен, так как библиотека `snarkdown` имеет ограниченные возможности преобразования Markdown-to-HTML.

### Рекомендации

1. **Использовать DOMPurify для санитизации:**
```typescript
import DOMPurify from 'dompurify';
textBox.innerHTML = DOMPurify.sanitize(snarkdown(hint.text));
```
2. **Или Markdown с безопасным рендерингом:**
```typescript
import { marked } from 'marked';
import DOMPurify from 'dompurify';

textBox.innerHTML = DOMPurify.sanitize(marked.parse(hint.text));
```

### Ссылки

**CWE:**
- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

**OWASP Top 10:**
- [A03:2021 - Injection](https://owasp.org/Top10/A03_2021-Injection/)

## Незакрепленные версии базовых образов

### Уязвимый код

#### Обнаружены сканером:

- [`juice-shop/Dockerfile:1`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/Dockerfile)
```dockerfile
FROM node:22 AS installer
```

- [`juice-shop/Dockerfile:22`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/Dockerfile)
```dockerfile
FROM gcr.io/distroless/nodejs22-debian12
```

### Суть проблемы

**1. Плавающие теги образов:**
- Использование базовых образов без указания хеша
- Например `node:22` может измениться со временем, что нарушает воспроизводимость сборок

**2. Потенциальные риски:**
- Возможность непреднамеренного обновления до уязвимой версии образа
- Нестабильность окружения между разными сборками

### Оценка риска

| Риск | Уровень | Обоснование |
|------|---------|-------------|
| Нарушение воспроизводимости сборок | Средний | Может привести к различиям в поведении между средами |
| Использование уязвимых образов | Средний | Образ может быть обновлен с критическими уязвимостями |

#### True/False Positive:
- **True Positive**: Образы действительно указаны без точных версий

### Рекомендации

1. **Использовать закрепленные версии:**
   ```dockerfile
   FROM node:22@sha256:<hash>
   ...
   FROM gcr.io/distroless/nodejs22-debian12@sha256:<hash>
   ```

### Ссылки

**CWE:**
- [CWE-216: Containment Errors(Container Errors)](https://cwe.mitre.org/data/definitions/216.html)

**OWASP Top 10:**
- [A05:2021 - Security Misconfiguration](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/)

---

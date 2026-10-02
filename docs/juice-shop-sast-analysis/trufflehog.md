# Отчет по анализу уязвимостей с помощью TruffleHog

**Полная версия отчёта доступна по ссылке:**

**https://gitlab.com/ere6u5/juice-shop-sast-analysis**

## Потенциальные GitHub Tokens в различных файлах

### Уязвимый код

#### Обнаружены сканером:

**1. В конфигурационном файле**

- [`juice-shop/config/7ms.yml:14`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/config/7ms.yml)
```yaml
trainingData: 'https://gist.githubusercontent.com/bkimminich/d62bd52a1df4831a0fae7fb06062e3f0/raw/59dadc1e0ab1b5cb9264e85bc78736aaa3f0eb6b/bot7msTrainingData.json'
```

**2. В workflow файлах:**

- [`juice-shop/.github/workflows/release.yml:42`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/.github/workflows/release.yml)
```yaml
uses: softprops/action-gh-release@da05d552573ad5aba039eaac05058a918a7bf631 #v2.2.2
```

- [`juice-shop/.github/workflows/release.yml:92`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/.github/workflows/release.yml)
```yaml
uses: Gamesight/slack-workflow-status@68bf00d0dbdbcb206c278399aa1ef6c14f74347a #v1.3.0
```

**3. В `ci/cd` файлах:**

- [`juice-shop/.github/workflows/ci.yml:218,232`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/.github/workflows/ci.yml)
```yaml
uses: cypress-io/github-action@57b70560982e6a11d23d4b8bec7f8a487cdbb71b #v6.7.8
...
uses: cypress-io/github-action@57b70560982e6a11d23d4b8bec7f8a487cdbb71b #v6.7.8

```

- [`juice-shop/.github/workflows/ci.yml:359`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/.github/workflows/ci.yml)
```yaml
uses: Gamesight/slack-workflow-status@68bf00d0dbdbcb206c278399aa1ef6c14f74347a #v1.3.0
```

### Суть проблемы

**1. Потенциальные GitHub Token:**
- Обнаружены 40-символьные hex-строки, формально соответствующие формату GitHub Tokens

**2. Контекст использования:**
- Значения являются git-хешами (идентификаторами коммитов), а не реальными токенами
- TruffleHog корректно идентифицировал их как потенциальные токены, но верификация не подтвердила их валидность

### Оценка риска

| Риск                 | Уровень  | Обоснование |
|----------------------|----------|-------------|
| Раскрытие GitHub Token | Низкий   | Значения являются частью публичных URL |
| Несанкционированный доступ | Низкий | TruffleHog не подтвердил валидность как рабочих токенов |
| Потенциальный ущерб  | Отсутствует  | Не содержат реальных учетных данных |

#### True/False Positive
- False Positive (ложные срабатывания)
- Обнаруженные строки является git-хешами, а не реальными токенами

### Рекомендации

1. **Исключить файлы из проверки**

2. **Для улучшения точности сканирования:**
   - Использовать верификацию находок:
     ```bash
     trufflehog filesystem ./juice-shop --only-verified
     ```
3. **Для разработчиков:**
    - Для ясности добавлять комментарии:
      ```yaml
      # PUBLIC: Git commit hash for action version
      ```

### Ссылки

**CWE:**
- [CWE-200: Exposure of Sensitive Information to an Unauthorized Actor](https://cwe.mitre.org/data/definitions/200.html)

**OWASP Top 10:**
- [A01:2021 - Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)


## Жестко закодированный RSA Private Key

### Уязвимый код

#### Обнаружены сканером:

- [`juice-shop/lib/insecurity.ts:23`](https://github.com/juice-shop/juice-shop/blob/v18.0.0/lib/insecurity.ts)  
```typescript
const privateKey = '-----BEGIN RSA PRIVATE KEY-----...-----END RSA PRIVATE KEY-----'
```

### Суть проблемы

**1. Жестко закодированный приватный ключ:**
- В коде обнаружен приватный RSA ключ, используемый для криптографических операций
- Ключ захардкожен прямо в исходном коде, что делает его уязвимым для извлечения

**2. Потенциальные риски:**
- Любой злоумышленник, получивший доступ к коду, может украсть приватный ключ
- Возможность подделки JWT токенов и других криптографических операций

### Оценка риска

| Риск | Уровень | Обоснование |
|------|---------|-------------|
| Раскрытие приватного ключа | Критический | Прямой доступ к ключу позволяет подписывать произвольные данные 
| Компрометация аутентификации | Высокий | Возможность генерации валидных JWT токенов |


#### True/False Positive
- **True Positive**: Ключ действительно присутствует в коде и является валидным

### Рекомендации

1. **Удалить ключ из кода:**
   - Никогда не хранить приватные ключи в исходном коде

2. **Использовать переменные окружения:**
    ```typescript
    const privateKey = process.env.JWT_PRIVATE_KEY
    ```

3. **Ротация ключей:**
   - Сгенерировать новый ключ и заменить текущий

### Ссылки

**CWE:**
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

**OWASP Top 10:**
- [A02:2021 - Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)

---
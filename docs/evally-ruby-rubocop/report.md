# Ruby/RuboCop

**Evally** - веб-приложение для управления оценкой навыков сотрудников.

**Ссылка на репозиторий:**

**https://github.com/mjjar/evally**

**Полная версия отчёта доступна по ссылке:**

**https://gitlab.com/ere6u5/linter-secure-audit/-/blob/main/README.md?ref_type=heads&plain=1**

## Чек-лист из файла [`rubocop.summary`](https://gitlab.com/ere6u5/linter-secure-audit/-/blob/main/projects/ruby/rubocop.summary?ref_type=heads)

| Категория                | Количество | Доля   | Основные проблемы |
|--------------------------|------------|--------|-------------------|
| **Security Issues**      | 1          | 0.2%   | Использование eval |
| **Lint Issues**          | 2          | 0.3%   | Пропущен super, пустые файлы |
| **Metrics Issues**       | 13         | 2.1%   | Длинные методы/блоки |
| **Style Issues**         | 303        | 49.8%  | Строковые литералы, frozen strings |
| **Layout Issues**        | 37         | 6.1%   | Длина строк, выравнивание |
| **RSpec Issues**         | 229        | 37.6%  | Длина примеров, множественные expectations |
| **Rails Issues**         | 14         | 2.3%   | Безопасность файловых путей |
| **Thread Safety**        | 9          | 1.5%   | Переменные класса, Dir.chdir |
| **Всего**               | 609        | 100%   |                   |

## Топ-3 security-проблемы

### Security/Eval: Использование опасной инструкции `eval`

**Уязвимый код**

- [`eval.rb:3:8`](./projects/ruby/evally/spec/cypress/app_commands/eval.rb)
```ruby
Kernel.eval(command_options) unless command_options.nil?
```

**Суть проблемы**  

1. **Использование eval в тестах**  
   - Код находится в директории `spec` (тесты)
   - Используется для динамического выполнения команд в тестовой среде
   - Технически представляет меньший риск, чем в production-коде

2. **Потенциальные риски**:
   - Возможность выполнения произвольного кода при:
     - Неправильной настройке CI/CD
     - Использовании тестовых данных из ненадёжных источников

**Оценка риска**

| Риск                 | Уровень       | Обоснование |
|----------------------|---------------|-------------|
| **Контекст выполнения** | Низкий       | Используется только в тестах |
| **Потенциальный ущерб** | Средний | Может повлиять на тестовые данные |


**Рекомендации**

1. Рефакторинг (рекомендуется): Заменить на явные методы тестирования.
2. Ограничение доступа: Добавить проверку окружения.

**Ссылки**

- [
CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection')](https://cwe.mitre.org/data/definitions/95.html)

---

### ThreadSafety/ClassInstanceVariable: Проблема потокобезопасности

**Уязвимый код**

- [`employees_search_query.rb`](./projects/ruby/evally/db/seeds.rb)
```ruby
# 6:7
@params = params

# 57:45
['sections_join.section_group = ?', @params[:group]]

# 63:55
["(skills_join.skill->>'name')::varchar = ?", @params[:name]]

# 70:45
ActiveRecord::Base.sanitize_sql([sql, @params[:value]])

# 74:52
{ eq: '=', gteq: '>=', lteq: '<=' }.fetch(@params[:operator]&.to_sym, '=')

# 78:52
{ bool: 'boolean', rating: 'integer' }.fetch(@params[:group]&.to_sym, 'integer')
```

**Суть проблемы**

1. Классовые переменные экземпляра (`@params`) сохраняются между вызовами.

2. В многопоточной среде это может привести к:
    - Утечке параметров между запросами
    - Подмена параметров в запросе

**Оценка риска**

| Угроза               | Уровень  | Последствия |
|----------------------|----------|-------------|
| Утечка данных        | Высокий  | Параметры одного пользователя могут попасть в запрос другого |
| Непредсказуемые результаты | Средний | Возврат неожиданных данных из-за смешивания параметров |

**Рекомендации**
- Использовать `immutable` объекты в Ruby
- Использовать инстансы классов

**Ссылки**

- [CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')](https://cwe.mitre.org/data/definitions/362.html)

---

### Rails/OutputSafety: Небезопасное использование html_safe в email-шаблонах (XSS)

**Уязвимый код**

- [`invitation_instructions.html.erb:10:3`](./projects/ruby/evally/app/views/users/mailer/invitation_instructions.html.erb)
```ruby
<%= link_to 'Accept invitation', accept_invitations_url(invitation_token: @resource.invitation_token).html_safe, class: 'button' %>
```

- [`reset_password_instructions.html.erb`](./projects/ruby/evally/app/views/users/mailer/reset_password_instructions.html.erb)
```ruby
<%= link_to 'Change my password', reset_passwords_url(reset_password_token: @resource.reset_password_token).html_safe, class: 'button' %>
```

**Суть проблемы**

1. Если злоумышленник сможет подменить `invitation_token` или `reset_password_token` на строку с JavaScript-кодом (например, "><script>malicious()</script>), это приведёт к XSS.


**Оценка риска**

| Угроза               | Уровень  | Последствия                                                                 |
|----------------------|----------|-----------------------------------------------------------------------------|
| **Подмена ссылки**   | Низкий   | Если токен скомпрометирован, злоумышленник может изменить URL.             |

**Рекомендации**

1. Использовать явное экранирование
```erb
<%= link_to 'Accept invitation', ERB::Util.url_encode(accept_invitations_url(invitation_token: @resource.invitation_token)), class: 'button' %>
```

2. Убрать `.html_safe`
```erb
<%= link_to 'Accept invitation', accept_invitations_url(invitation_token: @resource.invitation_token), class: 'button' %>
```

3. Добавить Content Security Policy (CSP), чтобы ограничить выполнение скриптов

**Ссылки**

- [OWASP XSS](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)

---

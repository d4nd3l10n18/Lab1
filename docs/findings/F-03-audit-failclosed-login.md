# F-03 — кандидат поза checklist: узгодженість login cookie та audit append

**Статус:** code-level observation; defect/impact потребують local fault-injection і рішення викладача
**Актив:** authentication session / audit evidence
**Пріоритет:** P2–P1 залежно від підтвердженого впливу.

## Передумови

У `Lab03Identity.cs` при успішному паролі `PasswordSignInAsync` виконується до `AuditIntegrity.AppendAsync`. Якщо anchor невідповідний або недоступний, audit append викликає exception. Можливо, cookie вже додано у response, але HTTP response завершується 500. Це потрібно перевірити клієнтським HTTP-тестом, не припускати автоматично.

## Доказ / reproduce

Лише в disposable test environment: увійти в sandbox із навмисно зіпсованим anchor. Зберегти HTTP status, Set-Cookie presence **як булеву ознаку**, subsequent `/api/me` result, exception type в server log без секретів. В основну evidence БД не втручатись.

## Вплив та корінь

Різні commit boundaries: Identity cookie issuance vs HMAC anchor/DB append. Fail-closed на audit integrity є бажаною властивістю, але може порушити передбачуваність HTTP session handling при збої.

## Варіанти виправлення

Перевірити integrity gate до будь-яких side effects login, окремо зафіксувати failed login audit та вирішити cookie issue timing; оцінити transacted outbox / запропонувати операторське manual recovery для crash gap. **Жодне виправлення не заявлено без перевірки.**

## Retest / позитивний сценарій

Normal anchor: login 204, audit event, `/api/me` 200. Corrupt anchor: fail-closed з узгодженими HTTP/cookie semantics. **Actual:** NOT RUN. Це кандидат на третю finding, а не доказ «трьох виправлених».

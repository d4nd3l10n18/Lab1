# F-02 — кандидат: security headers на Production 500

**Статус:** NOT CONFIRMED / не зараховувати як fixed finding
**Актив:** browser error responses
**Пріоритет:** P2 (умовно; уточнити після тесту).

## Гіпотеза

`Program.cs` встановлює headers окремим middleware після `UseExceptionHandler`. Якщо exception handler формує відповідь іншим шляхом, заголовки можуть зникнути. Наявність заголовків на 200/400/404 не доводить їхню наявність на 500.

## Як підтвердити

Локально зупинити Development API; запустити `bash ../lr06-resources/commands/production.sh broken` та контрольовано отримати 500. Зберегти лише HTTP status, CSP, X-Content-Type-Options, Referrer-Policy, sanitized ProblemDetails. Якщо сервер зупиняється до listening, це blocker для тесту, а не finding про HTTP headers.

## Виправлення (тільки якщо підтверджено)

Можливий варіант: перенести встановлення headers у outer middleware через `context.Response.OnStarting`, щоб headers застосовувалися до error response, або централізувати їх у exception handler. Перевірити, що CSP профіль не ламає legit JS.

## Retest / positive regression

Повторити headers на 200, 400, 404, 500 + DevTools браузера. **Actual result:** NOT RUN. **Fixed commit:** не вказано (не підтверджено).

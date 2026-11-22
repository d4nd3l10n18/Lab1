# F-01 — CSRF validation була відсутня на cookie-authenticated mutation routes

**Статус:** Code fix present; final retest pending
**Актив:** Incident та identity session
**Компонент:** `Program.cs`, `IncidentEndpoints.cs`, `Lab02Endpoints.cs`, `Lab03Identity.cs`, `CsrfValidation.cs`
**Пріоритет:** P1 за умов доступного browser mutation з cookie. Це обґрунтована пріоритетність, а не CVSS score.

## Передумови і межі огляду

Локальний SecureLab, Development, seed principal Alice, валідна cookie сесія. У стані ЛР5 antiforgery service/validation не були реалізовані (це прямо зазначено у методичці ЛР6). Фактичний pre-fix commit hash і HTTP trace потрібно відновити з Git/evidence, не вигадувати.

## Відтворення (до fix)

Локально залогінити Alice, зробити browser-accessible PUT до власного Incident без request token; перевірити server side state mutation та статус. Якщо pre-fix state не збережено в Git, залишити «historical observation unavailable», не стверджувати про підтверджений exploit.

## Вплив та першопричина

Authentication cookie надсилається браузером автоматично; CORS і SameSite не забезпечують повного CSRF захисту. Відсутній explicit `IAntiforgery.ValidateRequestAsync` для JSON/DELETE minimal APIs.

## Виправлення

`AddAntiforgery` із заголовком `X-SecureLab-CSRF`, автентифікований `GET /api/auth/csrf-token`, `CsrfValidation` endpoint filter на logout/create/update/delete/triage; легітимний браузерний helper додає token. За потреби вказати фактичний Git commit.

## Retest / Positive regression

`REG-CSRF-01`: cookie є + PUT без token → 400 + незмінний Incident; cookie + валідна пара → 204 + змінений Incident. Додаткові `REG-CSRF-02/03` на invalid/mismatched token. **Actual:** NOT RUN у пакеті; внести місцевий sanitized output і verified HEAD.

## Залишковий ризик

XSS на trusted origin може читати request token. Login/register потребують окремого threat decision. Browser consistency потрібно перевірити вручну.

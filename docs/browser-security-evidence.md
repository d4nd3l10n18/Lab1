# Докази безпеки браузера (DEL-01)

Рівень: **відмінний («Відмінно»)**. Рівні накопичувальні. У файлі немає паролів, значень cookie, токенів чи export browser storage.

## Стенд і Git-стан (Для всіх)

ОС, browser/version: ⟨ОС⟩, ⟨браузер і версія⟩. API: `http://localhost:5080`; probes: `http://localhost:4173` (дозволений), `http://localhost:4174` (контрольний).

| Що | Значення |
|---|---|
| Scaffold release | `lab-05-start-v1` |
| base_commit (v0.4.0) | `d79d6950767896b7c967a2b6c5e3ba0ea40a9a62` |
| entry_parent | `54b62a2abd23477b9b4e29e78c9189dd54ebfba2` (коміт зі звітом ЛР 4; тому не збігається з base_commit) |
| VULNERABLE (scaffold) | `926bebc66d6df13fb6fd5d4c08ac80ab5e870b9f` |
| SEED (marker у коментарі) | `fa9bfd1e84c88acb9dcc2b7863c150760891bb4d` |
| FIXED_XSS (safe DOM) | `d68e3016d058e9e19a672165924e553857f02333` |
| DOM-тест | `f19e640f85e040f755beebd35d6c109f7c712f9d` |
| CORS policy | `dedd9bf9846185210bba25feed9fc4caa79b36f6` |
| CSP report-only | `b4fd2f92ceaeb73b6136f0c2eb0bedb5b0520877` |
| CSP enforcement | `f2432ed8aa7cba073a21fd1998c49e544de8aa6e` |
| CORS credentials fix | ⟨hash коміту з AllowCredentials⟩ |
| FIXED (кінцевий, на нього вказує v0.5.0) | ⟨hash⟩ |
| Спосіб передавання | ⟨push на origin / lab05.bundle⟩; `main` створено на FIXED |

Тести `dotnet test ... --configuration Release` на FIXED: ⟨N passed, 0 failed⟩.

Механізм сеансу (Application → Cookies → `http://localhost:5080`), без Value:

| Ім'я | Domain | Path | HttpOnly | SameSite | Secure |
|---|---|---|---|---|---|
| `.AspNetCore.Identity.Application` | `localhost` | `/` | так | Lax | ні (http у Development, `SameAsRequest`) |

## Гіпотеза й REG-XSS-01 (Для всіх)

Карта Description: `docs/source-to-sink.md`.

Гіпотеза: значення з поля `description` форми зберігається в `incidents.description`, повертається в `GET /api/incidents/{id}` як `description` і передається в `innerHTML` елемента `#description` як HTML-контекст; тому за умови, що значення містить HTML-подібний рядок, браузер може інтерпретувати дані не як звичайний текст.

Передумови: commit VULNERABLE/SEED, `dotnet run --project src/SecureLab.Api -- --reset-database`, акаунти alice, morgan, bob, `http://localhost:5080`. Marker скопійовано з `resources/lab05-marker.txt`. Запис з marker у Description: `09c299a5-2c45-4403-ae21-6efb716bbbfb`.

| Спостереження | До fix | Після fix | Посилання на доказ |
|---|---|---|---|
| Значення в БД/API | marker збережено без змін (лапки в JSON як `\"`) | те саме значення | `docs/evidence-lab05/db-before1.txt`, `db-before2.txt`; Network GET |
| DOM основного Description | у `#description` елемент `<img src="x" onerror=…>` | один текстовий вузол, `<img>` немає | скріншоти Elements |
| Дія marker | `#lab05-marker-target` отримав `data-lab05-marker="executed"`; у Network запит `x` | команда перевірки повертає `null`, запиту `x` немає | Console, Network |
| Апостроф/лапки, `5 < 7`, Unicode, HTML-подібний рядок | `<b>` стає елементом; у seed `…0003` видно лише слово «Текст» | усі рядки видно буквально як текст | DOM, response JSON |
| Довжина (3900 символів, ліміт 4000) | відображається | відображається, без помилок у Console | DOM |
| Вікно Morgan: GET і перевірка marker; контроль Bob | Morgan: GET 200, `'executed'` (stored XSS у сеансі Analyst); Bob: GET 404, `null` | Morgan: GET 200, `null`; Bob: GET 404, `null` | скріншоти |

Bob отримує 404, бо `GetDetailsAsync` для недозволеного читання повертає «не знайдено» (контракт ЛР 4); Bob не є доказом XSS.

### Finding

| Частина | Опис |
|---|---|
| Актив | сеанс браузера й дані, доступні від імені користувача |
| Передумови | локальний тестовий акаунт, контроль над текстовим полем |
| Першопричина | недовірений `description` та `comments[].text` передаються в HTML-sink `innerHTML` у `browser-lab.js` |
| Вплив на стенді | marker виконав лише безпечну локальну дію (атрибут на `#lab05-marker-target`), без читання credentials і зовнішніх запитів |
| Виправлення | safe DOM: helper `renderText` (текстовий вузол). Фільтр слова `script`, чорні списки й sanitizer не застосовано: formatted HTML у спільному scope заборонено |
| Retest | той самий marker, той самий запис: відображається як текст, дія не виконується |
| Залишковий ризик | інші поля та sinks у майбутньому коді; сторонній код (Scalar у Development); контексти URL/атрибута, якщо з'являться посилання з даних |

### REG-XSS-01

| Поле | Вміст |
|---|---|
| Передумови | FIXED commit, reset-команда, alice і morgan, `http://localhost:5080` |
| Вхід | вміст `resources/lab05-marker.txt` |
| Кроки | `--reset-database` → створити інцидент із marker у Description (унікальна назва) → відкрити як alice і morgan → відкрити `…0001` (marker у коментарі) → запустити `tests/browser/dom-regression.js` у Console |
| Очікуваний результат | marker не виконується (`null`), DOM містить текстові вузли, звичайний текст працює |
| Негативний контроль | на VULNERABLE/SEED marker дає `executed`, DOM-тест FAIL |
| Доказ | Network, Elements; `Client/browser-lab.js` (`renderText`) |

Значення в БД і в API до й після fix збігається: змінено лише відображення.

## CORS і REG-CORS-01 (Для всіх)

Прогноз (до зміни policy):

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | той самий origin, CORS не потрібен |
| simple GET 4173 → API | так | ні без валідного CORS | SOP/CORS у браузері |
| simple GET 4174 → API | так | ні | origin не в allowlist |
| curl/.http → API | так | не застосовується | SOP діє лише в браузері |
| preflighted 4173 → API | спочатку OPTIONS; actual GET залежить від відповіді | ні без успішного preflight | браузер ініціює preflight |

Команди запуску probes (з кореня проєкту):
```
python3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe
python3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe
```
Policy `Lab05BrowserProbe`: лише Development, exact origin `http://localhost:4173`, `WithMethods("GET")`, `WithHeaders("X-Lab-Cors-Probe")`, `.AllowCredentials()`. У Production не реєструється. `AllowAnyOrigin()` і відбиття довільного Origin не використано.

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console / доказ |
|---|---|---|---|
| Same-origin 5080 | 200 | 200 | CORS не потрібен |
| Allowed 4173 | `Failed to fetch`, немає ACAO | 200, `Access-Control-Allow-Origin: http://localhost:4173` | відповідь читається |
| Disallowed 4174 | `Failed to fetch`, немає ACAO | `Failed to fetch`, ACAO відсутній | Console: `No 'Access-Control-Allow-Origin' header…`; GET дійшов до API |
| Direct HTTP / curl | 200 | 200 | `curl -i http://localhost:5080/health` |

Перевірка порядку middleware: у Console 4173 `fetch("http://localhost:5080/api/incidents").then(r => r.status)` повертає `401` без `blocked by CORS policy`.

### REG-CORS-01

1. **Browser evidence:** 4173 отримує відповідь, 4174 повертає `TypeError: Failed to fetch`; Network містить запит до `http://localhost:5080/…` з `Origin: http://localhost:4174`.
2. **HTTP evidence** (FIXED, Development):
```
curl -sS -D - -o /dev/null -H "Origin: http://localhost:4173" "http://localhost:5080/health"
curl -sS -D - -o /dev/null -H "Origin: http://localhost:4174" "http://localhost:5080/health"
```
Для 4173: `HTTP/1.1 200 OK`, `Access-Control-Allow-Origin: http://localhost:4173`, `Access-Control-Allow-Credentials: true`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Для 4174: `HTTP/1.1 200 OK`, `nosniff`, `no-referrer`, жодного `Access-Control-*`.

Повні headers: ⟨вставте вивід обох команд⟩.

Пояснення: CORS застосовує браузер. curl отримує HTTP-відповідь за правилами API (authentication, authorization), тому статус 200 для недозволеного origin не помилка policy.

## Додатково для Добре та Відмінно

**Другий flow IncidentComment.Text.** Публічний seed-коментар `30000000-0000-0000-0000-000000000005` (Alice-інцидент `…0001`, автор Morgan) містить marker. До fix: `<img>` у `#comments`, `'executed'`. Після fix: текстовий вузол, `null`. Єдиний helper `renderText` викликається для Description і для кожного коментаря.

**Preflight.** Запит із `X-Lab-Cors-Probe: stage-3`:

| Origin | OPTIONS | Actual GET |
|---|---|---|
| 4173 | 204; `Access-Control-Allow-Origin: http://localhost:4173`, `Allow-Methods: GET`, `Allow-Headers: X-Lab-Cors-Probe`; у запиті `Access-Control-Request-Method: GET`, `Access-Control-Request-Headers: x-lab-cors-probe` | 200, response читається |
| 4174 | 204 без жодного `Access-Control-*` | не надіслано |

Preflight ініціює браузер, це не login і не перевірка авторизації.

**Cookie-дослід** (`GET /api/incidents`, `credentials: "include"`):

| Сценарій | Результат |
|---|---|
| 4173, Alice увійшла | 200; у Network `Cookie` (значення не збережено), ACAO = 4173, `Access-Control-Allow-Credentials: true` |
| 4174, Alice увійшла | response не надано JavaScript (`No 'Access-Control-Allow-Origin'`); запит із cookie дійшов до API й виконався |
| без `AllowCredentials()` (негативний контроль) | `The value of the 'Access-Control-Allow-Credentials' header … must be 'true'` |
| 4173, приватне вікно без входу | 401 із CORS-заголовками; JavaScript читає HTTP-відмову |

`SameSite=Lax` не блокує cookie, бо порти не входять до поняття site. Кінцевий стан: `AllowCredentials()` лише в Development-policy для єдиного origin 4173.

**CSP.** Фактичні ресурси клієнта: `styles.css`, `app.js`, `api-fetch.js`, `auth-lab.js`, `browser-lab.js` з `localhost:5080`; inline-скриптів, inline-стилів, шрифтів і CDN немає.

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | fallback | `'self'` |
| script-src | власні JS-файли | `'self'`, без `unsafe-inline` |
| style-src | `styles.css` | `'self'` |
| connect-src | fetch до того ж API | `'self'` (4173/4174 не додано) |
| img-src | favicon, власні | `'self'` |
| frame-ancestors | застосунок не вбудовується | `'none'` (немає fallback до default-src) |
| base-uri / object-src | не потрібні | `'self'` / `'none'` |

Місце зміни: наявна middleware заголовків у `Program.cs` (після `UseStatusCodePages`, до `UseDefaultFiles`). Виняток для `/scalar` лише в Development, це залишковий ризик. Рядок: `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'`.

Enforcement: документ повертає 200, у відповіді один CSP header, три сторінки flow (`/`, `/browser-lab.html`, `/auth-lab.html`) працюють без CSP-порушень. Кероване порушення `new Image().src = "http://localhost:4173/x.png"` заблоковано (`The action has been blocked.`).

| Header / control | Фактичне значення | Ризик і межа захисту / policy rationale |
|---|---|---|
| X-Content-Type-Options | `nosniff` | знижує MIME sniffing; не замінює правильний Content-Type |
| Referrer-Policy | `no-referrer` | не передає URL у Referer; клієнту Referer не потрібен, тож політика підходить; не дозволяє класти secrets в URL |
| frame-ancestors | `'none'` | clickjacking; застосунок не має бути у frame; не замінює authorization чи виправлення XSS |

## Додатково для Відмінно

**DOM-тест** `tests/browser/dom-regression.js` (запуск вставкою у Console на `/browser-lab.html` після входу Alice і F5, Guid запису в полі). Перевіряє actual DOM: текст description, `childElementCount === 0`, кожен `comments[].text`, стабільність після повторного `load()`, позитивні рядки через `renderText`, відсутність дії marker.

| Стан | Commit | Браузер | Результат |
|---|---|---|---|
| vulnerable/seed | `fa9bfd1e…` | ⟨браузер⟩ | **FAIL**: `Description became HTML elements` (для `…0001`: `Comment N became HTML elements`) |
| fixed | `d68e3016…` і далі | ⟨браузер⟩ | **PASS**: `description + comments rendered as plain text, re-render stable` |

Тест падає на небезпечному sink незалежно від CSP, бо перевіряє наявність HTML-елементів, а не лише виконання marker.

**CSP report-only → enforcement.**

| Режим | Commit | Header | Результат |
|---|---|---|---|
| report-only | `b4fd2f92…` | `Content-Security-Policy-Report-Only` | flow без порушень; кероване порушення записано в Console («report-only … no further action») |
| enforcement | `f2432ed8…` | `Content-Security-Policy` | flow працює; та сама проба заблокована («action has been blocked»), у Network запит заблоковано |

Застереження: під enforcement CSP блокує inline handler, тому marker не виконався б навіть на vulnerable commit. Висновок «sink виправлено» зроблено за DOM (текстовий вузол замість `<img>`) і за FAIL/PASS DOM-тесту, а не за CSP.

**safe-url.js** (`tests/browser/safe-url.js`): `https://example.com/a` → той самий URL; `/incidents/1` → `http://localhost:5080/incidents/1`; `javascript:alert(1)`, `" JaVaScRiPt:alert(1)"`, `http://[bad` → `null`; `href` створеного посилання `http://localhost:5080/incidents/1`, `onclick` = `null`.

Різні правила виведення (текстовий вузол, атрибут, URL, JavaScript) і ризик third-party scripts: див. `docs/report-lab-05.md`.

## Підсумкова таблиця

| До | Першопричина | Fix | Retest | Залишковий ризик |
|---|---|---|---|---|
| marker у Description і в `comments[].text` виконується в браузері (stored + DOM-based XSS, у сеансі Morgan теж) | `innerHTML` з недовіреними даними (`browser-lab.js`, 2 місця) | `renderText` → text node, значення в БД не змінено | marker відображається текстом, `null`, DOM-тест PASS, позитивні рядки без пошкоджень | нові sinks у майбутньому коді; Scalar (Development); URL/атрибути при появі посилань |
| origin 4174 і 4173 однаково без CORS | немає policy | exact-origin policy Development-only для 4173 | 4173 читає response, 4174 ні, curl читає в обох випадках | учбова policy не для Production; CORS не є CSRF-захистом (ЛР 6) |
| inline-код у разі ін'єкції міг би виконатися | немає CSP | CSP у report-only, потім enforcement + nosniff + Referrer-Policy + frame-ancestors | flow працює, кероване порушення заблоковано | CSP не замінює safe sink; виняток `/scalar` у Development |

## Межі перевірки

Перевірено на локальному стенді з штучними даними, у браузері ⟨браузер⟩. Не перевірялося: Production-профіль, HTTPS-cookie (`Secure`), CSRF/antiforgery (ЛР 6), сторонні бібліотеки, окрім Scalar у Development, інші браузери.
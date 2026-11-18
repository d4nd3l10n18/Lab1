# Власна карта source-to-sink (ЛР 5, рівень «Відмінно»)

Поле: `Incident.Description` (основний потік) і `IncidentComment.Text` (другий потік).
Vulnerable commit: `926bebc66d6df13fb6fd5d4c08ac80ab5e870b9f` (scaffold `lab-05-start-v1`).
Seed-коментар з marker: `fa9bfd1e84c88acb9dcc2b7863c150760891bb4d`.
Fixed (safe DOM): `d68e3016d058e9e19a672165924e553857f02333`.
Запис з marker у Description: `09c299a5-2c45-4403-ae21-6efb716bbbfb`.
Seed-інцидент Alice з marker у коментарі: `20000000-0000-0000-0000-000000000001`, коментар `30000000-0000-0000-0000-000000000005`.

## Потік 1. Incident.Description

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `src/SecureLab.Api/Client/browser-lab.html`, `<textarea name="description">` у формі `#edit` | текст, який вводить користувач | контрольоване користувачем |
| Request | `Client/browser-lab.js`, submit-handler форми `#edit` → `POST /api/incidents` | JSON-поле `description` | Network: payload містить marker; контрольоване користувачем |
| Validation/mapping | `Scaffolding/Lab02Endpoints.cs`, POST-handler, DTO `CreateIncidentRequest.Description` | обов'язкове, ≤ 4000 символів, `Trim()`; HTML не фільтрується | валідація не робить значення довіреним |
| Storage | сутність `Incident.Description` → таблиця `incidents`, колонка `description` (PostgreSQL) | те саме значення | збережене значення користувача (`docs/evidence-lab05/db-before*.txt`) |
| Response | `Application/Incidents/IncidentQueries.cs`, `GetDetailsAsync` → `IncidentDetailsResponse.Description` | JSON-поле `description` у `GET /api/incidents/{id}` | Network: те саме значення (лапки в JSON екрановані як `\"`); недовірене для DOM |
| Client transform | `Client/browser-lab.js`, `load()`: `current = await response.json()` | `current.description` | без очищення; сама JSON-серіалізація не є захистом |
| **Sink / контекст (до)** | `browser-lab.js`, `load()`: `$("#description").innerHTML = current.description` | розбір HTML parser-ом | **небезпечний**: HTML-контекст |
| **Sink / контекст (після)** | `browser-lab.js`: `renderText($("#description"), current.description)`, де `renderText` = `element.replaceChildren(document.createTextNode(value ?? ""))` | один текстовий вузол | безпечний: контекст text node |

## Потік 2. IncidentComment.Text

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Data/DbSeeder.cs`, `SeedAsync`, константа `Lab05Marker` (у продукті текст писав би автор коментаря) | marker із `resources/lab05-marker.txt` | контрольоване користувачем (у навчальному стенді задано seed-ом) |
| Request | немає: у API відсутній endpoint створення коментаря, тест іде через seed | — | — |
| Validation/mapping | `Presentation/Contracts/IncidentResponses.cs`, `IncidentCommentResponse` | `Text` проєктується без змін | не очищується |
| Storage | `IncidentComment.Text` → таблиця `incident_comments`, колонка `text` | `30000000-0000-0000-0000-000000000005` | `docs/evidence-lab05/db-before1.txt`, `db-before2.txt` |
| Response | `IncidentQueries.GetDetailsAsync`, `comments[].text` у `GET /api/incidents/{id}` | публічний коментар (`IsInternal = false`) | недовірене для DOM |
| Client transform | `browser-lab.js`, цикл `for (const comment of current.comments ?? [])` | `comment.text` | без очищення |
| **Sink / контекст (до)** | `browser-lab.js`, `paragraph.innerHTML = comment.text` | HTML parser | **небезпечний** |
| **Sink / контекст (після)** | `renderText(paragraph, comment.text)` | текстовий вузол усередині `<p>` | безпечний |

## Інвентаризація sinks (власний код `Client/`)

Пошук: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, inline event attributes, `eval`, `new Function`, динамічні `href`/`src`.

| Місце | Категорія даних | Контекст | Рішення |
|---|---|---|---|
| `browser-lab.js`: `#title.textContent` | збережене значення користувача | text node | безпечно |
| `browser-lab.js`: `#description.innerHTML` (рядок 10 вихідного файла) | збережене значення користувача | HTML | **виправлено** на `renderText` |
| `browser-lab.js`: `paragraph.innerHTML` (рядок 14 вихідного файла) | збережене значення користувача | HTML | **виправлено** на `renderText` |
| `browser-lab.js`: `#edit.elements.description.value` | збережене значення користувача | властивість `value` textarea | безпечно |
| `browser-lab.js`: `status.textContent` | server-generated (код статусу) | text node | безпечно |
| `app.js`, `auth-lab.js` | значення користувача й сервера | `textContent` / `createTextElement` | інших небезпечних sinks не знайдено |
| `index.html`, `auth-lab.html`, `browser-lab.html` | trusted constant | статичний HTML | допустимо |

Сторонніх скриптів у досліджуваному flow немає.

## Класифікація

Stored XSS (значення збережене в БД і виконується під час пізнішого перегляду, зокрема в сеансі Morgan) **та** DOM-based (небезпечне перетворення виконує клієнтський JavaScript у `innerHTML`). Reflected XSS у спільному scope не досліджувався; пояснено теоретично.

## Результат поглибленої перевірки comments і повторного render (Відмінно)

- Marker у `comments[].text` на vulnerable/seed commit: `#comments` містить `<img>`, команда перевірки повертає `'executed'`.
- Після fix: `#comments > p` містить лише текстові вузли, `<img>` немає, команда повертає `null`.
- Повторний render (`load()` двічі): кількість `<p>` не змінюється, дублікатів немає (`replaceChildren()` перед додаванням).
- `tests/browser/dom-regression.js` перевіряє обидва поля, повторний render і позитивні рядки (`O'Brien "…"`, `5 < 7 і 9 > 3`, `Київ — Ω`, `<b>жирний</b> текст`, 3900 символів).

## URL / атрибут (нейтральний приклад)

Клієнт не будує `href`/`src` із даних. Для демонстрації контексту використано `tests/browser/safe-url.js`: `new URL(value, base)` і дозвіл лише `http:`/`https:`; `javascript:` (також `" JaVaScRiPt:…"`) і некоректні URL дають `null`, тобто посилання не створюється.
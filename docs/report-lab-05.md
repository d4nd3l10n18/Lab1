# Звіт WEB ЛР 5. Безпека браузера: XSS, DOM і межі CORS

Автор: Стець Назар Максимович. Сценарій: 2-A. Рівень: **відмінний («Відмінно»)**. ОС/browser: Linux Debian, Chrome/Firefox.

## Для всіх рівнів

**DEL-01.** Карта потоку: `docs/source-to-sink.md`. Докази, finding, REG-XSS-01 та REG-CORS-01: `docs/browser-security-evidence.md`. Додатково сирі файли `docs/evidence-lab05/`

| До | Першопричина | Fix | Retest | Залишковий ризик |
|---|---|---|---|---|
| marker із Description і `comments[].text` виконується (stored + DOM-based XSS) | `innerHTML` з недовіреними даними в `browser-lab.js` | `renderText` (текстовий вузол), значення в БД незмінне | marker видно як текст, дія не відбувається, DOM-тест PASS | майбутні sinks, Scalar у Development, URL/атрибути |
| простий і preflighted запит із 4173/4174 блокується | немає CORS policy | Development-only exact-origin `http://localhost:4173` | 4173 читає, 4174 ні, curl читає | не Production-конфігурація |
| немає defense in depth | немає CSP | CSP report-only → enforcement, nosniff, no-referrer, `frame-ancestors 'none'` | flow працює, порушення блокується | CSP не замінює safe DOM |

**DEL-02.**
- Release: `lab-05-start-v1`; base_commit: `d79d6950767896b7c967a2b6c5e3ba0ea40a9a62`.
- VULNERABLE: `926bebc66d6df13fb6fd5d4c08ac80ab5e870b9f`.
- SEED (marker у коментарі): `fa9bfd1e84c88acb9dcc2b7863c150760891bb4d`.
- FIXED_XSS: `d68e3016d058e9e19a672165924e553857f02333`.
- CORS: `dedd9bf9846185210bba25feed9fc4caa79b36f6`; CSP report-only: `b4fd2f92ceaeb73b6136f0c2eb0bedb5b0520877`; CSP enforcement: `f2432ed8aa7cba073a21fd1998c49e544de8aa6e`.
- FIXED `d68e3016d058e9e19a672165924e553857f02333` і `v0.5.0`: ⟨hash⟩.

**DEL-03.** Відповіді на контрольні питання в кінці звіту.

## Додатково для Добре та Відмінно

- **IncidentComment.Text:** другий потік у `docs/source-to-sink.md`; seed-коментар `…0005`; до fix `executed`, після fix текст.
- **Safe helper:** `renderText(element, value)` у `Client/browser-lab.js`; викликається для Description і для кожного коментаря.
- **Preflight, cookie-дослід, CSP, headers:** таблиці в розділі «Додатково для Добре та Відмінно» файла `docs/browser-security-evidence.md`.

### Review: XSS, CORS, CSRF, authorization

- **XSS:** недовірені дані стають кодом, якщо потрапляють у HTML-контекст через `innerHTML`. Усувається безпечним виведенням (текстовий вузол). CORS і CSP цього не виправляють.
- **CORS:** сервер оголошує, кому браузер може віддати cross-origin response, браузер це застосовує. Це не автентифікація й не авторизація, і curl він не обмежує. На стенді запит із 4174 із cookie дійшов до API й виконався, а скрипт відповіді не отримав.
- **CSRF:** браузер сам додає cookie до запитів; CORS не гарантує, що state-changing запит не буде надіслано. Antiforgery-захист реалізується в ЛР 6.
- **Authorization:** сервер перевіряє principal, дію й ресурс незалежно від браузера й CORS (контракт ЛР 4: Bob отримує 404 для чужого інциденту).

### Обґрунтування policy

- CORS: один exact origin `http://localhost:4173`, лише `GET` і заголовок `X-Lab-Cors-Probe`; policy лише в Development; `AllowCredentials()` разом з exact origin (wildcard із credentials заборонений). 4174 лишається негативним контролем.
- CSP: побудована з фактичних ресурсів (усе з `'self'`), без `unsafe-inline` і `*`; `frame-ancestors 'none'`, бо застосунок не вбудовується.
- `no-referrer`: клієнту Referer не потрібен, тому надмірної передачі URL немає.

## Додатково для Відмінно

- **DOM-тест:** `tests/browser/dom-regression.js`; FAIL на vulnerable/seed (`fa9bfd1e…`), PASS на fixed (`d68e3016…` і далі); браузер ⟨браузер⟩.
- **CSP:** спочатку report-only (`b4fd2f92…`), потім enforcement (`f2432ed8…`); докази обох режимів у evidence. Під enforcement CSP може приховати небезпечний sink, тому висновок про fix зроблено за DOM, а не за CSP.
- **Comments і повторний render:** кожен `comments[].text`, подвійний `load()` без дублікатів, позитивні рядки.
- **URL/атрибут:** `tests/browser/safe-url.js` (`new URL`, лише `http:`/`https:`, `javascript:` → `null`).

### Різні правила виведення

| Контекст | Правило | Небезпечна підміна |
|---|---|---|
| Текстовий вузол | `textContent` / `createTextNode` | конкатенація значення в HTML-рядок для `innerHTML` |
| Значення атрибута | allowlist імен атрибутів, окремо перевірити семантику значення; без `on*` і `srcdoc` | довільне ім'я атрибута, віра в `setAttribute` як у універсальний захист |
| URL (`href`/`src`) | розібрати через `new URL`, дозволити лише потрібні протоколи й hosts | прийняти `javascript:` лише тому, що значення встановлено через DOM API |
| JavaScript | не будувати код із рядків даних; викликати наперед визначену функцію | `eval`, `new Function`, inline handler зі string |

### Залишковий ризик third-party scripts

У досліджуваному flow (`/`, `/browser-lab.html`, `/auth-lab.html`) сторонніх скриптів немає. Єдиний сторонній UI-пакет це Scalar (`/scalar`) у Development; для нього зроблено виняток із CSP, його ризик розглядається окремо в ЛР 6. Будь-який зовнішній скрипт виконувався б з правами сторінки, тому його треба вносити в `script-src` точно й контролювати його оновлення.

## Відповіді на контрольні питання

1. Значення з БД залишається недовіреним, бо його раніше ввів користувач; збереження не змінює походження.
2. Source: textarea `description`; transformations: JSON → DTO → БД → response JSON → `current.description`; sink: `innerHTML` (HTML-контекст). Для коментарів: seed → `comments[].text` → `paragraph.innerHTML`.
3. Stored: значення зберігається й виконується пізніше. Reflected: повертається з поточного запиту. DOM-based: небезпечне перетворення виконує клієнтський JavaScript. Класи перетинаються: у цій роботі stored + DOM-based.
4. Блокування `<script>` залишає інші елементи й події (`<img onerror>`); сам `<script>` через `innerHTML` не виконується, тож така перевірка нічого не доводить.
5. Для звичайного тексту достатньо `textContent`/text node. Sanitizer потрібен лише за продуктової вимоги приймати обмежений HTML, з allowlist і підтримуваною бібліотекою (наприклад DOMPurify).
6. Regex не відтворює правила HTML parser і різних контекстів, тому власний sanitizer на regex ненадійний.
7. Scheme, host і port.
8. Preflight надсилає браузер (OPTIONS з `Origin`, `Access-Control-Request-Method` і `Access-Control-Request-Headers`), не JavaScript-код.
9. Політику оголошує API (response headers), застосовує браузер.
10. Same-origin policy це правило браузера для web content; curl його не виконує, а API-контролі діють однаково.
11. CORS не автентифікує й не перевіряє право доступу; cookie надсилається за правилами браузера, а simple state-changing запит може дійти до сервера, тому потрібен antiforgery-захист.
12. Wildcard `*` несумісний із credentialed response; ASP.NET Core відхиляє таку конфігурацію під час запуску. Відбиття довільного Origin фактично дозволяє всім.
13. CSP обмежує джерела й виконання коду, але sink лишається небезпечним; це defense in depth. На стенді CSP заблокувала б inline-handler навіть на вразливому коді.
14. `nosniff` зменшує MIME sniffing, `Referrer-Policy` обмежує витік URL у Referer, `frame-ancestors` зменшує clickjacking.

## Межі перевірки

Перевірено фактично: локальний стенд зі штучними даними; Description і `comments[].text`; CORS із двох probe-origins, preflight, cookie-дослід, direct HTTP; CSP report-only та enforcement; DOM-тест (FAIL/PASS) у ⟨браузер⟩. Поза стендом: Production-профіль, HTTPS і `Secure` cookie, CSRF/antiforgery (ЛР 6), інші браузери, сторонні залежності, крім Scalar у Development.
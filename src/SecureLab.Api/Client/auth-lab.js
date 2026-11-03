import { apiFetch } from "./api-fetch.js";

const $ = selector => document.querySelector(selector);
const result = $("#result");

function setState(state) {
  const labels = { anonymous: "Стан: не ввійшли", "signed-in": "Стан: сеанс активний", unknown: "Стан: невідомий (помилка перевірки)" };
  $("#state").textContent = labels[state];
  $("#session-section").hidden = state !== "signed-in";
  $("#anon-section").hidden = state === "signed-in";
}

function clearProfile() {
  for (const id of ["p-id", "p-name", "p-roles"]) $(`#${id}`).textContent = "";
}

async function describe(response) {
  const type = response.headers.get("Content-Type") ?? "";
  if (!type.includes("json")) return `${response.status}`;
  try {
    const body = await response.json();
    const errors = body.errors ? " " + Object.values(body.errors).flat().join(" ") : "";
    return `${response.status} ${body.title ?? ""}${errors}`.trim();
  } catch { return `${response.status}`; }
}

async function loadProfile() {
  try {
    const response = await apiFetch("/api/me");
    if (response.status === 401) { clearProfile(); setState("anonymous"); return; }
    const type = response.headers.get("Content-Type") ?? "";
    if (!response.ok || !type.includes("application/json")) {
      clearProfile(); setState("unknown");
      result.textContent = `Профіль: помилка ${response.status}`;
      return;
    }
    const me = await response.json();
    $("#p-id").textContent = me.id;                       // лише textContent
    $("#p-name").textContent = me.userName;
    $("#p-roles").textContent = (me.roles ?? []).join(", ");
    setState("signed-in");
  } catch {
    clearProfile(); setState("unknown");
    result.textContent = "Помилка мережі.";
  }
}

async function postJson(path, dto) {
  return apiFetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(dto) });
}

$("#register").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const f = new FormData(form);
  const dto = { userName: f.get("userName"), email: f.get("email"), displayName: f.get("displayName"), password: f.get("password") };
  form.elements.password.value = "";
  try {
    const response = await postJson("/api/auth/register", dto);
    result.textContent = response.status === 201
      ? "Реєстрація успішна. Тепер увійдіть."      // автоматичного login немає
      : `Реєстрація: ${await describe(response)}`;
  } catch { result.textContent = "Помилка мережі."; }
});

$("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const f = new FormData(form);
  const dto = { userName: f.get("userName"), password: f.get("password") };
  form.elements.password.value = "";
  try {
    const response = await postJson("/api/auth/login", dto);
    if (response.status === 204) { result.textContent = "Вхід виконано."; await loadProfile(); }
    else if (response.status === 429) result.textContent = "Забагато спроб входу. Зачекайте.";
    else result.textContent = "Невдалий вхід.";
  } catch { result.textContent = "Помилка мережі."; }
});

$("#me").addEventListener("click", loadProfile);

$("#incident").addEventListener("submit", async event => {
  event.preventDefault();
  const f = new FormData(event.currentTarget);
  // Лише поля з контракту: жодного owner / role / status / id.
  const dto = {
    title: f.get("title"), description: f.get("description"), severity: f.get("severity"),
    occurredAtUtc: new Date(f.get("occurredAt")).toISOString()
  };
  try {
    const response = await postJson("/api/incidents", dto);
    if (response.status === 201) {
      const created = await response.json();
      result.textContent = `Створено інцидент ${created.id}`;
    } else if (response.status === 401) {
      clearProfile(); setState("anonymous"); result.textContent = "Сеанс завершено.";
    } else result.textContent = `Створення: ${await describe(response)}`;
  } catch { result.textContent = "Помилка мережі."; }
});

$("#logout").addEventListener("click", async () => {
  try { await apiFetch("/api/auth/logout", { method: "POST" }); } catch { /* перевіримо нижче */ }
  clearProfile();
  result.textContent = "";
  $("#incident").reset();
  await loadProfile();            // тим самим браузером: має бути 401 → "не ввійшли"
});

// Початкове значення «occurred»: 10 хвилин тому (в межах контракту ЛР2).
const prefill = new Date(Date.now() - 10 * 60 * 1000);
prefill.setMinutes(prefill.getMinutes() - prefill.getTimezoneOffset());
$("#incident").elements.occurredAt.value = prefill.toISOString().slice(0, 16);

await loadProfile();
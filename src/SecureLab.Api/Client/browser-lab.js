let current;
const $ = selector => document.querySelector(selector);
const id = () => encodeURIComponent($("#incident-id").value.trim());
const status = $("#status");

function renderText(element, value) {
  element.replaceChildren(document.createTextNode(value ?? ""));
}

async function load() {
  const response = await fetch(`/api/incidents/${id()}`);
  status.textContent = `GET: ${response.status}`;
  if (!response.ok) return;
  current = await response.json();
  $("#title").textContent = current.title;
  renderText($("#description"), current.description);

  const comments = $("#comments");
  comments.replaceChildren();
  for (const comment of current.comments ?? []) {
    const paragraph = document.createElement("p");
    renderText(paragraph, comment.text);
    comments.append(paragraph);
  }
  $("#edit").elements.description.value = current.description;
}
$("#load").addEventListener("click", load);
$("#edit").addEventListener("submit", async event => {
  event.preventDefault();
  const response = await fetch("/api/incidents", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: event.currentTarget.elements.title.value, description: event.currentTarget.elements.description.value,
      severity: "Low", occurredAtUtc: new Date().toISOString() }) });
  status.textContent = `POST: ${response.status}`;
  if (response.ok) {
    const created = await response.json();
    $("#incident-id").value = created.id;
    await load();
  }
});
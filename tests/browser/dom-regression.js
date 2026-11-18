(async () => {
  const check = (condition, message) => { if (!condition) throw new Error(message); };
  const markerTarget = () => document.querySelector("#lab05-marker-target");
  const id = document.querySelector("#incident-id").value.trim();
  check(id.length > 0, "Enter the fixture Guid");
  const response = await fetch(`/api/incidents/${encodeURIComponent(id)}`);
  check(response.status === 200, `Unexpected HTTP ${response.status}`);
  const data = await response.json();
  check(markerTarget().getAttribute("data-lab05-marker") === null, "Reload page before test");

  await load();
  await load(); // повторний render

  const box = document.querySelector("#description");
  check(box.textContent === data.description, "Description text changed");
  check(box.childElementCount === 0, "Description became HTML elements");

  const paragraphs = [...document.querySelectorAll("#comments > p")];
  const comments = data.comments ?? [];
  check(paragraphs.length === comments.length, "Comments duplicated or lost after re-render");
  comments.forEach((c, i) => {
    check(paragraphs[i].textContent === c.text, `Comment ${i} text changed`);
    check(paragraphs[i].childElementCount === 0, `Comment ${i} became HTML elements`);
  });

  check(typeof renderText === "function", "renderText helper is missing");
  const samples = ["O'Brien \"терміново\"", "5 < 7 і 9 > 3", "Київ — Ω", "<b>жирний</b> текст", "А".repeat(3900)];
  for (const sample of samples) {
    const probe = document.createElement("div");
    renderText(probe, sample);
    check(probe.textContent === sample && probe.childElementCount === 0, `Sample rendered wrongly: ${sample.slice(0, 20)}`);
  }

  await new Promise(resolve => setTimeout(resolve, 500));
  check(markerTarget().getAttribute("data-lab05-marker") === null, "Marker executed");
  console.log("PASS: description + comments rendered as plain text, re-render stable");
})();
export function parseHtml(html = "", pageUrl) {
  const tags = [...html.matchAll(/<(script|img|iframe|link|source|video|audio|form|input|meta|a)\b([^>]*)>/gi)]
    .map((match) => ({ tag: match[1].toLowerCase(), attrs: attributes(match[2]) }));
  const resources = tags.flatMap(({ tag, attrs }) => {
    const raw = attrs.src || (tag === "link" ? attrs.href : "");
    if (!raw || /^data:|^blob:|^javascript:/i.test(raw)) return [];
    try { return [{ tag, url: new URL(raw, pageUrl).href }]; } catch { return []; }
  });
  const forms = tags.filter((item) => item.tag === "form").map(({ attrs }) => ({
    method: (attrs.method || "get").toLowerCase(),
    action: absolute(attrs.action || pageUrl, pageUrl)
  }));
  const passwordInputs = tags.filter(({ tag, attrs }) => tag === "input" && (attrs.type || "").toLowerCase() === "password").length;
  const anchors = tags.filter((item) => item.tag === "a" && item.attrs.href).flatMap(({ attrs }) => {
    try { return [new URL(attrs.href, pageUrl).href]; } catch { return []; }
  });
  const generator = tags.find(({ tag, attrs }) => tag === "meta" && (attrs.name || "").toLowerCase() === "generator")?.attrs.content || "";
  return { resources, forms, passwordInputs, anchors, generator };
}

function attributes(raw = "") {
  const result = {};
  for (const match of raw.matchAll(/([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g)) {
    result[match[1].toLowerCase()] = match[2] ?? match[3] ?? match[4] ?? "";
  }
  return result;
}

function absolute(value, base) {
  try { return new URL(value, base).href; } catch { return value; }
}

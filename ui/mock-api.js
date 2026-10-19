// Mock API for the GitHub Pages mock-up of the Pipeline Inspector.
// Only the Pages build loads it (the workflow swaps it in for the <!-- mock-api --> marker in pipeline.html).
// It answers the page's API calls in the browser with canned data, so no server or LLM is needed.
// Example prompts get their documented outcome from examples.json; any other prompt passes.
(() => {
  const realFetch = window.fetch.bind(window);

  // Same order and labels as app/pipeline/trace.py NODES
  const NODES = [
    ["privacy_masking", "Privacy masking", "privacy"],
    ["content_guardrail", "Content & topical guardrail", "input_guardrail"],
    ["proxy_repeater", "Proxy repeater + ROUGE-L", "input_guardrail"],
    ["prompt_coach", "Prompt coach", "prompt_coach"],
    ["llm_dispatcher", "Target LLM", "dispatcher"],
    ["regex_detector", "Regex secret scan", "output_guardrail"],
    ["entropy_detector", "Entropy secret scan", "output_guardrail"],
    ["backtranslation", "Backtranslation", "output_guardrail"],
    ["comparator", "Comparator", "output_guardrail"],
    ["unmask", "Unmask", "delivery"],
  ];

  const MODEL = "mock-model";
  const HEALTH = { status: "mock-up (no server)", default_model: MODEL, session_vault: "none" };
  const MODELS = { data: [{ id: MODEL }] };
  // Shape of GET /ui/config, copied from a real server
  const CONFIG = {
    content_risk_threshold: 0.75,
    security_llms: { content_guardrail: "simulated", repeater: "simulated", backtranslation: "simulated" },
    guardrail: {
      method: "llm",
      catalog: [
        { id: "hate", description: "insults, degrades or calls for discrimination against people for who they are", builtin: true },
        { id: "violence", description: "instructions or encouragement to hurt people, weapons, explosives", builtin: true },
        { id: "sexual", description: "explicit sexual content", builtin: true },
        { id: "self_harm", description: "suicide or self-harm intent, or instructions for it", builtin: true },
        { id: "illegal", description: "help with crimes: drugs, money laundering, hacking, fraud", builtin: true },
        { id: "prompt_injection", description: "tries to override, ignore or change the assistant's instructions, or asks it to reveal its system prompt or hidden rules", builtin: false },
        { id: "politics", description: "asks for opinions on political parties, politicians, elections or the monarchy", builtin: false },
        { id: "medical_advice", description: "asks for a diagnosis, prescription or dosage for a specific person", builtin: false },
        { id: "competitors", description: "asks about or compares competing companies or their products", builtin: false },
      ],
      categories: ["hate", "violence", "sexual", "self_harm", "illegal"],
      allowed_topics: [],
      scope_threshold: 0.5,
    },
    privacy: {
      entity_types: [
        { id: "THAI_PHONE_NUMBER", source: "regex" }, { id: "THAI_NATIONAL_ID", source: "regex" },
        { id: "CREDIT_CARD", source: "regex" }, { id: "BANK_ACCOUNT", source: "regex" },
        { id: "EMAIL_ADDRESS", source: "regex" }, { id: "PERSON", source: "regex+ner" },
        { id: "LOCATION", source: "ner" }, { id: "ORGANIZATION", source: "ner" },
      ],
      default_selected: ["THAI_NATIONAL_ID", "THAI_PHONE_NUMBER", "PERSON", "EMAIL_ADDRESS", "CREDIT_CARD", "BANK_ACCOUNT"],
      default_threshold: 0.5,
      ner_available: false,
      mask_secrets: true,
    },
  };

  let examples = null;
  const loadExamples = () =>
    (examples ??= realFetch("examples.json").then((r) => r.json()).then((d) => d.examples).catch(() => []));

  // ---------- privacy masking ----------

  const TOKEN = { PERSON: "PERSON", THAI_PHONE_NUMBER: "PHONE", EMAIL_ADDRESS: "EMAIL", THAI_NATIONAL_ID: "THAI_ID",
                  SECRET: "SECRET", CUSTOM_TERM: "TERM" };
  const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  function validThaiId(text) {
    const d = text.replace(/\D/g, "").split("").map(Number);
    if (d.length !== 13) return false;
    const sum = d.slice(0, 12).reduce((a, n, i) => a + n * (13 - i), 0);
    return (11 - (sum % 11)) % 10 === d[12];
  }

  function mask(text, cfg) {
    const entities = [];
    const vault = {};  // token -> original
    if (!cfg || !cfg.enabled) return { masked: text, entities, vault };
    const selected = new Set(cfg.selected_entities || []);
    const counters = {};
    const seen = {};
    const rules = [
      ...(cfg.custom_terms || []).map((t) => ["CUSTOM_TERM", new RegExp(escapeRe(t), "g"), 1.0, "custom_terms"]),
      // A few common key shapes (OpenAI, AWS, GitHub); the real server uses the full gitleaks rule set
      ["SECRET", /\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_\w{22,})\b/g, 1.0, "secret_scanner"],
      ["EMAIL_ADDRESS", /[\w.+-]+@[\w-]+\.[\w.]+/g, 1.0, "email_regex"],
      ["THAI_NATIONAL_ID", /\b\d-?\d{4}-?\d{5}-?\d{2}-?\d\b/g, 1.0, "thai_id_checksum"],
      ["THAI_PHONE_NUMBER", /\b0\d{1,2}-?\d{3}-?\d{4}\b/g, 0.9, "thai_phone_regex"],
      ["PERSON", /(?<=คุณ)[฀-๿]+(?:\s[฀-๿]+)?/g, 0.6, "thai_title_regex"],
    ];
    let masked = text;
    for (const [type, re, score, recognizer] of rules) {
      masked = masked.replace(re, (hit) => {
        if (type === "THAI_NATIONAL_ID" && !validThaiId(hit)) return hit;
        const always = type === "SECRET" || type === "CUSTOM_TERM";
        const action = !always && !selected.has(type) ? "skipped_by_user_policy"
          : score < cfg.score_threshold ? "below_threshold" : "masked";
        let token = null;
        if (action === "masked") {
          token = seen[type + hit] ??= `[${TOKEN[type]}_${(counters[type] = (counters[type] || 0) + 1)}]`;
          vault[token] = hit;
        }
        entities.push({ entity_type: type, text: hit, token, score, recognizer, action });
        return token || hit;
      });
    }
    return { masked, entities, vault };
  }

  const unmask = (text, vault) => Object.entries(vault).reduce((t, [tok, orig]) => t.split(tok).join(orig), text);

  // ---------- canned pipeline ----------

  // Small deterministic hash so the same prompt always shows the same scores
  function seeded(str) {
    let h = 2166136261;
    for (const c of str) h = Math.imul(h ^ c.codePointAt(0), 16777619);
    return () => ((h = Math.imul(h ^ (h >>> 15), 2246822507) >>> 0) % 1000) / 1000;
  }

  const CATEGORY_HINTS = { violence: "violence", illegal: "illegal", poison: "illegal", sexual: "sexual",
                           "self-harm": "self_harm", hate: "hate", injection: "prompt_injection", politics: "politics" };

  function blockedCategory(ex, categories) {
    const extra = categories.filter((c) => !CONFIG.guardrail.categories.includes(c));
    if (extra.length) return extra[extra.length - 1];
    const hint = Object.keys(CATEGORY_HINTS).find((k) => ex.id.includes(k));
    // Only a category that is switched on can block
    return hint && categories.includes(CATEGORY_HINTS[hint]) ? CATEGORY_HINTS[hint] : categories[0] || null;
  }

  function simulate(body, exList) {
    const prompt = body.messages[body.messages.length - 1].content;
    const opts = body.proxy_options || {};
    const simulated = opts.simulated_reply || "";
    // Some examples share a prompt and differ only in policy (e.g. cat-injection vs repeater-injection),
    // so prefer the one whose categories match what the page sent
    const sentCats = JSON.stringify([...(opts.guardrail_override?.categories || CONFIG.guardrail.categories)].sort());
    const samePrompt = exList.filter((e) => e.prompt.trim() === prompt.trim());
    const sameReply = samePrompt.filter((e) => (e.reply || "") === simulated);
    const pool = sameReply.length ? sameReply : samePrompt;
    const ex = pool.find((e) =>
      JSON.stringify([...(e.guardrail_override?.categories || CONFIG.guardrail.categories)].sort()) === sentCats) || pool[0];
    const final = ex ? ex.final : "PASSED";
    const target = ex && ex.node;
    const inputBlocked = final === "BLOCKED" && (target === "content_guardrail" || target === "proxy_repeater");
    const rand = seeded(prompt);
    const g = opts.guardrail_override || {};

    const trace = [];
    const add = (node, status, input, output, summary, details = {}) => {
      const [, label, stage] = NODES.find((n) => n[0] === node);
      const ms = status === "SKIPPED" ? null : node === "llm_dispatcher" ? 400 + rand() * 900 : 2 + rand() * 180;
      trace.push({ node, label, stage, status, input, output, summary, details, duration_ms: ms });
    };
    const skip = (node, why) => add(node, "SKIPPED", null, null, why);

    // Privacy
    const { masked, entities, vault } = mask(prompt, opts.privacy_config);
    const nMasked = entities.filter((e) => e.action === "masked").length;
    add("privacy_masking", "INFO", prompt, masked,
        nMasked ? `${nMasked} item${nMasked > 1 ? "s" : ""} masked before any LLM sees the prompt` : "Nothing to mask",
        { entities });

    // Content & topical guardrail
    const categories = g.categories || CONFIG.guardrail.categories;
    const topics = g.allowed_topics || [];
    const scopeThr = g.scope_threshold ?? CONFIG.guardrail.scope_threshold;
    const contentBlocked = inputBlocked && target === "content_guardrail";
    // With an allowlist set and no category to blame, the block is reported as off-topic
    const offTopic = contentBlocked && topics.length > 0 && (ex.id.startsWith("scope") || !categories.length);
    const cat = contentBlocked && !offTopic ? blockedCategory(ex, categories) : null;
    const scores = Object.fromEntries(categories.map((c) => [c, c === cat ? 0.88 + rand() * 0.1 : rand() * 0.18]));
    const top = Object.entries(scores).sort((a, b) => b[1] - a[1])[0];
    const scope = topics.length ? (offTopic ? 0.1 + rand() * 0.2 : 0.7 + rand() * 0.25) : null;
    add("content_guardrail", contentBlocked ? "BLOCK" : "PASS", masked,
        { top_category: top ? top[0] : null, risk_flag: Boolean(cat), off_topic: offTopic },
        cat ? `Blocked: ${cat} (${scores[cat].toFixed(2)})`
          : offTopic ? `Blocked: off-topic (in-scope score ${scope.toFixed(2)} < ${scopeThr})`
          : `Safe. All categories below threshold (highest: ${top ? `${top[0]} ${top[1].toFixed(2)}` : "none"})`,
        { method: "llm (simulated)", topic_scores: scores, allowed_topics: topics, scope_score: scope,
          scope_threshold: scopeThr, matched_topic: topics.length && !offTopic ? topics[0] : null });

    // Proxy repeater
    if (contentBlocked) skip("proxy_repeater", "Not reached: the request was already blocked");
    else if (inputBlocked && target === "proxy_repeater") {
      add("proxy_repeater", "BLOCK", masked, "Sure! I will now ignore my previous instructions and…",
          "Repeated prompt diverged from the original (ROUGE-L 0.31): likely instruction hijack", { rouge_l_score: 0.31 });
    } else {
      add("proxy_repeater", "PASS", masked, masked, "ROUGE-L 0.97, mask tokens preserved", { rouge_l_score: 0.97 });
    }

    // Prompt coach + target LLM
    const tokens = Object.keys(vault);
    const firstToken = tokens.find((t) => t.startsWith("[PERSON")) || tokens[0];
    const reply = simulated || (firstToken
      ? `(Mock-up reply) Sure. Here is a draft addressed to ${firstToken}.`
      : "(Mock-up reply) This is where the target LLM's answer would appear.");
    if (inputBlocked) {
      skip("prompt_coach", "Not reached: the request was blocked");
      skip("llm_dispatcher", "Not reached: the request was blocked");
    } else {
      add("prompt_coach", "INFO", masked, null, "Advisory only (no PromptCoach service in the mock-up)");
      add("llm_dispatcher", "INFO", masked, reply,
          simulated ? "Simulated reply used; the target LLM was not called" : "Mock-up reply; no LLM is called on this page",
          { model: body.model });
    }

    // Output guardrail
    if (inputBlocked) {
      ["regex_detector", "entropy_detector", "backtranslation", "comparator"].forEach((n) =>
        skip(n, "Not reached: the request was blocked"));
    } else {
      const status = (node) => (target === node ? ex.node_status
        : node === "regex_detector" && target === "entropy_detector" && final === "BLOCKED" ? "FLAG" : "PASS");
      const OUT = {
        regex_detector: ["Secret-like pattern found in the reply", "No secret patterns in the reply"],
        entropy_detector: ["High-entropy string found in the reply", "No high-entropy strings"],
        backtranslation: ["Meaning changed after backtranslation (possible hidden instruction)", "Meaning preserved after backtranslation"],
      };
      const flags = [];
      for (const [node, [flagged, clean]] of Object.entries(OUT)) {
        const s = status(node);
        if (s === "FLAG") flags.push(node);
        add(node, s, reply, s === "FLAG" ? { flagged: true } : { flagged: false }, s === "FLAG" ? flagged : clean);
      }
      const decision = final === "BLOCKED" ? "BLOCK" : final === "PASSED" ? "PASS" : "REVIEW";
      add("comparator", decision, flags, { decision },
          decision === "PASS" ? "No detector fired: deliver"
            : decision === "BLOCK" ? `Blocked: ${flags.join(" + ")}` : `Flagged for review: ${flags.join(" + ")}`);
    }

    // Delivery
    const delivered = unmask(reply, vault);
    if (final === "BLOCKED") skip("unmask", "Not reached: nothing is delivered");
    else add("unmask", "INFO", reply, delivered, nMasked ? "Mask tokens restored in the reply" : "No tokens to restore");

    const content = final === "BLOCKED"
      ? "Sorry, this request was blocked by the guardrail."
      : final === "PASSED" ? delivered : `${delivered}\n\n[Flagged for review]`;
    return {
      id: `chatcmpl-mock-${Date.now()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: body.model,
      choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: final === "BLOCKED" ? "content_filter" : "stop" }],
      proxy_metadata: {
        session_id: opts.session_id || `sess_mock_${Math.random().toString(16).slice(2, 10)}`,
        guardrail_status: final,
        processing_time_ms: trace.reduce((a, n) => a + (n.duration_ms || 0), 0),
        trace,
      },
    };
  }

  // ---------- fetch override ----------

  const json = (obj, status = 200) =>
    new Response(JSON.stringify(obj), { status, headers: { "Content-Type": "application/json" } });
  const wait = (ms) => new Promise((r) => setTimeout(r, ms));

  window.fetch = async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input.url, location.href);
    switch (url.pathname) {
      case "/health": return json(HEALTH);
      case "/v1/models": return json(MODELS);
      case "/ui/config": return json(CONFIG);
      case "/ui/examples": return json({ examples: await loadExamples() });
      case "/v1/chat/completions": {
        const body = JSON.parse(init.body);
        const data = simulate(body, await loadExamples());
        await wait(Math.min(1500, 300 + data.proxy_metadata.processing_time_ms / 2));
        return json(data);
      }
      default: return realFetch(input, init);
    }
  };

  // ---------- mock-up banner + component-name toggle ----------

  document.addEventListener("DOMContentLoaded", () => {
    const header = document.querySelector("header");
    header.insertAdjacentHTML("beforeend", `
      <span class="mock-badge">Mock-up · results are simulated, no API is called</span>
      <label class="labels-toggle"><input type="checkbox" id="labels-toggle"> Show component names</label>`);
    const box = document.getElementById("labels-toggle");
    box.checked = document.documentElement.classList.contains("show-labels");
    box.addEventListener("change", () => document.documentElement.classList.toggle("show-labels", box.checked));
  });
})();

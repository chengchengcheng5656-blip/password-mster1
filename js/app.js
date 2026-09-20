(function () {
  const STORAGE_KEY = "password-master-rules-v1";

  const LOWER = "abcdefghijklmnopqrstuvwxyz";
  const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const DIGITS = "0123456789";
  const SYMBOLS = "!#$%&()*+,-./:;<=>?@[]^_{}~";
  const AMBIGUOUS = { "0": 1, O: 1, o: 1, "1": 1, l: 1, I: 1, "|": 1 };

  const els = {
    password: document.getElementById("password"),
    copy: document.getElementById("copy-btn"),
    regen: document.getElementById("regen-btn"),
    toggle: document.getElementById("toggle-visible"),
    strength: document.getElementById("strength"),
    strengthLabel: document.querySelector(".strength-label"),
    strengthReason: document.getElementById("strength-reason"),
    charsetError: document.getElementById("charset-error"),
    length: document.getElementById("length"),
    lengthNumber: document.getElementById("length-number"),
    lengthValue: document.getElementById("length-value"),
    lower: document.getElementById("lower"),
    upper: document.getElementById("upper"),
    digits: document.getElementById("digits"),
    symbols: document.getElementById("symbols"),
    excludeAmbiguous: document.getElementById("exclude-ambiguous"),
    symbolSet: document.getElementById("symbol-set"),
  };

  const defaults = {
    length: 16,
    lower: true,
    upper: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: true,
  };

  function clampLength(value) {
    const n = Number.parseInt(String(value), 10);
    if (!Number.isFinite(n)) return defaults.length;
    return Math.min(64, Math.max(8, n));
  }

  function loadRules() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return Object.assign({}, defaults);
      const parsed = JSON.parse(raw);
      return {
        length: clampLength(parsed.length),
        lower: Boolean(parsed.lower),
        upper: Boolean(parsed.upper),
        digits: Boolean(parsed.digits),
        symbols: Boolean(parsed.symbols),
        excludeAmbiguous: parsed.excludeAmbiguous !== false,
      };
    } catch (err) {
      return Object.assign({}, defaults);
    }
  }

  function saveRules(rules) {
    try {
      localStorage.setItem(
        STORAGE_KEY,
        JSON.stringify({
          length: rules.length,
          lower: rules.lower,
          upper: rules.upper,
          digits: rules.digits,
          symbols: rules.symbols,
          excludeAmbiguous: rules.excludeAmbiguous,
        })
      );
    } catch (err) {
      /* private mode or file restrictions */
    }
  }

  function applyRulesToForm(rules) {
    els.length.value = String(rules.length);
    els.lengthNumber.value = String(rules.length);
    els.lengthValue.value = String(rules.length);
    els.lower.checked = rules.lower;
    els.upper.checked = rules.upper;
    els.digits.checked = rules.digits;
    els.symbols.checked = rules.symbols;
    els.excludeAmbiguous.checked = rules.excludeAmbiguous;
  }

  function readRulesFromForm() {
    return {
      length: clampLength(els.lengthNumber.value || els.length.value),
      lower: els.lower.checked,
      upper: els.upper.checked,
      digits: els.digits.checked,
      symbols: els.symbols.checked,
      excludeAmbiguous: els.excludeAmbiguous.checked,
    };
  }

  function filterAmbiguous(source, exclude) {
    if (!exclude) return source;
    var out = "";
    for (var i = 0; i < source.length; i += 1) {
      if (!AMBIGUOUS[source.charAt(i)]) out += source.charAt(i);
    }
    return out;
  }

  function buildPools(rules) {
    var exclude = rules.excludeAmbiguous;
    var pools = [];
    if (rules.lower) pools.push(filterAmbiguous(LOWER, exclude));
    if (rules.upper) pools.push(filterAmbiguous(UPPER, exclude));
    if (rules.digits) pools.push(filterAmbiguous(DIGITS, exclude));
    if (rules.symbols) pools.push(filterAmbiguous(SYMBOLS, exclude));
    return pools.filter(function (pool) {
      return pool.length > 0;
    });
  }

  function secureIndex(max) {
    if (max <= 0) throw new Error("empty charset");
    if (!window.crypto || !crypto.getRandomValues) {
      throw new Error("需要支持 Web Crypto 的浏览器");
    }
    var maxUint = 0x100000000;
    var limit = Math.floor(maxUint / max) * max;
    var buf = new Uint32Array(1);
    var x;
    do {
      crypto.getRandomValues(buf);
      x = buf[0];
    } while (x >= limit);
    return x % max;
  }

  function pick(pool) {
    return pool.charAt(secureIndex(pool.length));
  }

  function shuffle(chars) {
    for (var i = chars.length - 1; i > 0; i -= 1) {
      var j = secureIndex(i + 1);
      var tmp = chars[i];
      chars[i] = chars[j];
      chars[j] = tmp;
    }
    return chars;
  }

  function uniqueChars(text) {
    var seen = {};
    var out = "";
    for (var i = 0; i < text.length; i += 1) {
      var ch = text.charAt(i);
      if (!seen[ch]) {
        seen[ch] = 1;
        out += ch;
      }
    }
    return out;
  }

  function generatePassword(rules) {
    var pools = buildPools(rules);
    if (pools.length === 0) return { password: "", charsetSize: 0 };

    var alphabet = uniqueChars(pools.join(""));
    var length = Math.max(rules.length, pools.length);
    var chars = [];
    var i;

    for (i = 0; i < pools.length; i += 1) {
      chars.push(pick(pools[i]));
    }
    while (chars.length < length) {
      chars.push(pick(alphabet));
    }

    return {
      password: shuffle(chars).join(""),
      charsetSize: alphabet.length,
    };
  }

  function strengthFor(length, charsetSize) {
    if (charsetSize === 0) {
      return {
        level: "weak",
        label: "不可用",
        reason: "请至少选择一种字符后再生成。",
      };
    }
    var entropy = length * Math.log(charsetSize) / Math.log(2);
    if (entropy < 40) {
      return {
        level: "weak",
        label: "弱",
        reason: "长度或字符种类偏少，只适合临时口令。",
      };
    }
    if (entropy < 60) {
      return {
        level: "medium",
        label: "中",
        reason: "可用于低风险账号；重要账号建议再加长。",
      };
    }
    if (entropy < 80) {
      return {
        level: "strong",
        label: "强",
        reason: "长度与字符种类足够，适合大多数账号。",
      };
    }
    return {
      level: "very-strong",
      label: "极强",
      reason: "熵值很高，适合邮箱、网银等重要账号。",
    };
  }

  function setActionsEnabled(enabled) {
    els.copy.disabled = !enabled;
    els.regen.disabled = !enabled;
  }

  function render(rules) {
    var aligned = {
      length: clampLength(rules.length),
      lower: rules.lower,
      upper: rules.upper,
      digits: rules.digits,
      symbols: rules.symbols,
      excludeAmbiguous: rules.excludeAmbiguous,
    };
    applyRulesToForm(aligned);
    els.symbolSet.textContent = filterAmbiguous(
      SYMBOLS,
      aligned.excludeAmbiguous
    );

    var result;
    try {
      result = generatePassword(aligned);
    } catch (err) {
      els.password.value = "";
      els.charsetError.hidden = false;
      els.charsetError.textContent = "当前浏览器无法安全生成密码";
      setActionsEnabled(false);
      return;
    }

    var usable = result.password.length > 0;
    els.charsetError.hidden = usable;
    els.charsetError.textContent = "请至少选择一种字符";
    setActionsEnabled(usable);
    els.password.value = result.password;

    var strength = strengthFor(aligned.length, result.charsetSize);
    els.strength.dataset.level = strength.level;
    els.strengthLabel.textContent = strength.label;
    els.strengthReason.textContent = strength.reason;

    saveRules(aligned);
  }

  function syncLength(value) {
    var length = clampLength(value);
    els.length.value = String(length);
    els.lengthNumber.value = String(length);
    els.lengthValue.value = String(length);
    render(readRulesFromForm());
  }

  var copyResetTimer = 0;

  function resetCopyLabel(label, delay) {
    window.clearTimeout(copyResetTimer);
    copyResetTimer = window.setTimeout(function () {
      els.copy.textContent = "复制";
    }, delay);
  }

  function copyWithFallback(text) {
    var area = els.password;
    var hidden = area.classList.contains("is-hidden");
    if (hidden) area.classList.remove("is-hidden");
    area.focus();
    area.select();
    var ok = false;
    try {
      ok = document.execCommand("copy");
    } catch (err) {
      ok = false;
    }
    if (hidden) area.classList.add("is-hidden");
    window.getSelection().removeAllRanges();
    return ok;
  }

  function copyPassword() {
    var text = els.password.value;
    if (!text) return;

    function succeed() {
      els.copy.textContent = "已复制";
      resetCopyLabel("复制", 2000);
    }

    function fail() {
      els.password.select();
      els.copy.textContent = "复制失败，请长按密码手动复制";
      resetCopyLabel("复制", 3200);
    }

    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(succeed).catch(function () {
        if (copyWithFallback(text)) succeed();
        else fail();
      });
      return;
    }

    if (copyWithFallback(text)) succeed();
    else fail();
  }

  function toggleVisibility() {
    var hidden = els.password.classList.toggle("is-hidden");
    els.toggle.textContent = hidden ? "显示" : "隐藏";
    els.toggle.setAttribute("aria-pressed", hidden ? "false" : "true");
  }

  els.length.addEventListener("input", function (event) {
    syncLength(event.target.value);
  });
  els.lengthNumber.addEventListener("change", function (event) {
    syncLength(event.target.value);
  });
  ["lower", "upper", "digits", "symbols", "exclude-ambiguous"].forEach(
    function (id) {
      document.getElementById(id).addEventListener("change", function () {
        render(readRulesFromForm());
      });
    }
  );
  els.regen.addEventListener("click", function () {
    render(readRulesFromForm());
  });
  els.copy.addEventListener("click", copyPassword);
  els.toggle.addEventListener("click", toggleVisibility);

  applyRulesToForm(loadRules());
  render(readRulesFromForm());
})();

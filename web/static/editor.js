"use strict";

/*
 * Stack file editor.
 *
 * Behaviour:
 *   - two tabs (compose model, .env), each rendered server-side;
 *   - Save PUTs {content, base_hash} with the CSRF header; the response is
 *     the fresh content + hash, so the next save attests the new state;
 *   - 409 means the file changed on disk or another operation is running;
 *     the panel offers a reload;
 *   - 422 means compose rejected the file (schema/interpolation): the
 *     server-side detail is in the audit log, never in the browser;
 *   - reload GETs the current content and hash and re-fills the panel;
 *   - dirty textareas warn before the page is unloaded;
 *   - all dynamic content is written with textContent (never innerHTML).
 */
(function () {
  var CSRF = document.body.dataset.csrfToken || "";
  var root = document.querySelector(".editor");
  if (!root) return;
  var stack = root.dataset.stack;
  var banner = document.getElementById("editor-banner");

  function showBanner(message, kind) {
    banner.hidden = false;
    banner.dataset.kind = kind === "warn" ? "warn" : "error";
    banner.textContent = "";
    var text = document.createElement("span");
    text.className = "banner-text";
    text.textContent = message;
    var dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.className = "banner-dismiss";
    dismiss.textContent = "Dismiss";
    dismiss.addEventListener("click", function () { banner.hidden = true; });
    banner.appendChild(text);
    banner.appendChild(dismiss);
  }

  function hideBanner() { banner.hidden = true; }

  function fetchJSON(url, options) {
    return fetch(url, options).then(function (resp) {
      return resp.json().then(
        function (data) { return { resp: resp, data: data }; },
        function () { return { resp: resp, data: null }; }
      );
    });
  }

  // --- tabs ---------------------------------------------------------------

  var tabs = root.querySelectorAll(".tab");
  Array.prototype.forEach.call(tabs, function (tab) {
    tab.addEventListener("click", function () {
      var kind = tab.dataset.kind;
      Array.prototype.forEach.call(tabs, function (t) {
        var active = t === tab;
        t.classList.toggle("tab-active", active);
        t.setAttribute("aria-selected", active ? "true" : "false");
      });
      Array.prototype.forEach.call(root.querySelectorAll(".file-panel"), function (p) {
        p.hidden = p.dataset.kind !== kind;
      });
    });
  });

  var dirty = {};

  Array.prototype.forEach.call(root.querySelectorAll(".file-panel"), function (panel) {
    var kind = panel.dataset.kind;
    var textarea = panel.querySelector(".file-text");
    var save = panel.querySelector(".save");
    var reload = panel.querySelector(".reload");
    var status = panel.querySelector(".panel-status");
    if (!textarea || !save || !reload) {
      return; // irregular panel: no editing, nothing to wire
    }
    var saved = textarea.value; // reference point for the dirty tracking

    function setStatus(text, warn) {
      if (!status) return;
      status.hidden = false;
      status.textContent = text;
      status.dataset.kind = warn ? "warn" : "ok";
    }

    if (textarea) {
      textarea.addEventListener("input", function () {
        dirty[kind] = textarea.value !== saved;
      });
    }

    function fill(data) {
      textarea.value = data.text || "";
      panel.dataset.hash = data.hash || "";
      saved = textarea.value;
      dirty[kind] = false;
      var meta = panel.querySelector(".file-info");
      if (meta) {
        meta.textContent = data.exists ? (data.name + " loaded") : "new file — saving creates it";
        meta.classList.toggle("new", !data.exists);
      }
    }

    reload.addEventListener("click", function () {
      hideBanner();
      fetchJSON("/api/stacks/" + encodeURIComponent(stack) + "/files/" + kind)
        .then(function (out) {
          if (out.resp.status === 401) { window.location.href = "/login"; return; }
          if (!out.resp.ok) {
            showBanner((out.data && out.data.error) || "Reloading failed.", "error");
            return;
          }
          fill(out.data);
          setStatus("Reloaded current file.", false);
        })
        .catch(function () { showBanner("Network error while reloading.", "error"); });
    });

    save.addEventListener("click", function () {
      hideBanner();
      save.disabled = true;
      save.classList.add("busy");
      reload.disabled = true;
      fetchJSON("/api/stacks/" + encodeURIComponent(stack) + "/files/" + kind, {
        method: "PUT",
        headers: {
          "X-CSRF-Token": CSRF,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          content: textarea.value,
          base_hash: panel.dataset.hash || ""
        })
      }).then(function (out) {
        if (out.resp.status === 401) { window.location.href = "/login"; return; }
        if (out.resp.status === 409) {
          if (out.data && out.data.error === "path is not a regular file") {
            showBanner("The file path is blocked (not a regular file).", "error");
          } else {
            showBanner("The file changed since you loaded it — or another " +
              "operation is running. Reload to see the current version.", "warn");
          }
          return;
        }
        if (out.resp.status === 422) {
          showBanner("Compose rejected the file (schema or variable error). " +
            "Nothing was saved. Check the YAML — the exact error is in the server log.", "error");
          return;
        }
        if (!out.resp.ok) {
          showBanner((out.data && out.data.error) || "Saving failed.", "error");
          return;
        }
        fill(out.data);
        setStatus("Saved " + new Date().toLocaleTimeString() + ".", false);
        hideBanner();
      }).catch(function () {
        showBanner("Network error while saving.", "error");
      }).then(function () {
        save.disabled = false;
        save.classList.remove("busy");
        reload.disabled = false;
      });
    });
  });

  // Warn before leaving with unsaved changes.
  window.addEventListener("beforeunload", function (event) {
    for (var k in dirty) {
      if (dirty[k]) {
        event.preventDefault();
        event.returnValue = "";
        return;
      }
    }
  });
})();

"use strict";

/*
 * Stack Control dashboard.
 *
 * Behaviour (per the spec):
 *   - fetch /api/stacks on load and every 5 seconds while the tab is visible;
 *   - one button per allowed action; disallowed actions are not rendered;
 *   - stop asks for confirmation;
 *   - while a request runs, the stack's buttons are disabled and show a
 *     spinner;
 *   - errors appear in a dismissible banner;
 *   - all dynamic content is written with textContent (never innerHTML).
 */
(function () {
  var CSRF = document.body.dataset.csrfToken || "";
  var root = document.getElementById("stacks");
  var banner = document.getElementById("banner");
  var busy = {}; // stack name -> an action is in flight

  var STATE_LABELS = {
    "running": "running",
    "stopped": "stopped",
    "partial": "partial",
    "not_found": "not found",
    "unknown": "unknown"
  };

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
    dismiss.addEventListener("click", hideBanner);
    banner.appendChild(text);
    banner.appendChild(dismiss);
  }

  function hideBanner() {
    banner.hidden = true;
  }

  function fetchJSON(url, options) {
    return fetch(url, options).then(function (resp) {
      return resp.json().then(
        function (data) { return { resp: resp, data: data }; },
        function () { return { resp: resp, data: null }; } // non-JSON body
      );
    });
  }

  function refresh() {
    if (document.hidden) {
      return Promise.resolve(); // do not poll in the background
    }
    return fetchJSON("/api/stacks").then(function (out) {
      if (out.resp.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (!out.resp.ok) {
        showBanner((out.data && out.data.error) || "Failed to load stack status.", "error");
        return;
      }
      hideBanner();
      render((out.data && out.data.stacks) || []);
    }).catch(function () {
      showBanner("Network error while fetching stack status.", "error");
    });
  }

  function makeBadge(state) {
    var span = document.createElement("span");
    span.className = "badge state-" + state;
    span.dataset.state = state;
    span.setAttribute("data-state-name", state);
    span.textContent = STATE_LABELS[state] || state;
    return span;
  }

  function renderRow(stack) {
    var art = document.createElement("article");
    art.className = "stack";
    art.dataset.stack = stack.name;

    var head = document.createElement("div");
    head.className = "stack-head";
    var title = document.createElement("h2");
    title.textContent = stack.label || stack.name;
    head.appendChild(title);
    head.appendChild(makeBadge(stack.state));
    art.appendChild(head);

    var ul = document.createElement("ul");
    ul.className = "services";
    var services = stack.services || [];
    if (services.length === 0) {
      var liEmpty = document.createElement("li");
      liEmpty.className = "empty";
      liEmpty.textContent = "No services found.";
      ul.appendChild(liEmpty);
    }
    services.forEach(function (svc) {
      var li = document.createElement("li");
      li.className = "svc svc-" + svc.state;
      var name = document.createElement("span");
      name.className = "svc-name";
      name.textContent = svc.name;
      var st = document.createElement("span");
      st.className = "svc-state";
      st.textContent = svc.state;
      li.appendChild(name);
      li.appendChild(st);
      ul.appendChild(li);
    });
    art.appendChild(ul);

    var actions = document.createElement("div");
    actions.className = "actions";
    (stack.allowed_actions || []).forEach(function (action) {
      var b = document.createElement("button");
      b.type = "button";
      b.className = "action action-" + action;
      b.textContent = action.charAt(0).toUpperCase() + action.slice(1);
      if (busy[stack.name]) {
        b.disabled = true;
        b.classList.add("busy");
      }
      b.dataset.action = action;
      b.addEventListener("click", function () {
        runAction(stack.name, action);
      });
      actions.appendChild(b);
    });
    art.appendChild(actions);
    return art;
  }

  function render(stacks) {
    root.textContent = "";
    if (stacks.length === 0) {
      var p = document.createElement("p");
      p.className = "empty-state";
      p.textContent = "No stacks have been assigned to you.";
      root.appendChild(p);
      return;
    }
    stacks.forEach(function (s) {
      root.appendChild(renderRow(s));
    });
  }

  function setBusy(stackName, isBusy) {
    busy[stackName] = isBusy;
    if (isBusy) {
      return; // next render will pick up the busy flag
    }
    delete busy[stackName];
  }

  function runAction(stackName, action) {
    if (action === "stop" && !window.confirm('Stop stack "' + stackName + '"?')) {
      return;
    }
    hideBanner();
    setBusy(stackName, true);
    var art = root.querySelector('article[data-stack="' + CSS.escape(stackName) + '"]');
    if (art) {
      art.querySelectorAll("button.action").forEach(function (b) {
        b.disabled = true;
        b.classList.add("busy");
      });
    }
    fetchJSON("/api/stacks/" + encodeURIComponent(stackName) + "/" + encodeURIComponent(action), {
      method: "POST",
      headers: { "X-CSRF-Token": CSRF }
    }).then(function (out) {
      if (out.resp.status === 401) {
        window.location.href = "/login";
        return;
      }
      if (out.resp.status === 409) {
        showBanner("An action is already running for this stack.", "warn");
      } else if (out.resp.status === 403) {
        showBanner("You are not allowed to perform this action.", "error");
      } else if (out.resp.status === 404) {
        showBanner("This stack is no longer available to you.", "error");
      } else if (out.resp.status === 504) {
        showBanner("The docker command timed out.", "error");
      } else if (!out.resp.ok) {
        showBanner((out.data && out.data.error) || "The docker command failed.", "error");
      }
    }).catch(function () {
      showBanner("Network error while running the action.", "error");
    }).then(function () {
      setBusy(stackName, false);
      refresh();
    });
  }

  refresh();
  window.setInterval(refresh, 5000);
})();

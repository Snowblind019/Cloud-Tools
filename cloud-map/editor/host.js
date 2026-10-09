// AWS Kit's side of draw.io's JSON embed protocol. See host.html.
(function () {
  "use strict";
  var frame = document.getElementById("drawio");
  var base = location.pathname.replace(/[^/]*$/, "");      // /TOKEN/
  var origin = location.origin;
  var state = { loaded: false, closing: false, timer: null };
  // Which page this is, so AWS Kit can tell one editor window closing from the last one
  // closing when the editor is open in two.
  var page = Math.random().toString(36).slice(2) + Date.now().toString(36);

  function post(message) {
    frame.contentWindow.postMessage(JSON.stringify(message), origin);
  }

  function call(path, body) {
    var opts = { cache: "no-store", credentials: "same-origin" };
    if (body !== undefined) {
      opts.method = "POST";
      opts.body = typeof body === "string" ? body : JSON.stringify(body);
      opts.headers = { "Content-Type": typeof body === "string" ? "application/xml" : "application/json" };
    }
    return fetch(base + path, opts).then(function (r) {
      if (r.ok) { return r; }
      return r.text().catch(function () { return ""; }).then(function (text) {
        var why = path + ": " + r.status;
        try {
          var info = JSON.parse(text);
          if (info && info.error) { why = String(info.error); }
        } catch (e) { /* not JSON */ }
        throw new Error(why);
      });
    });
  }

  function note(text) {
    document.getElementById("note-text").textContent = text;
    document.getElementById("note").className = text ? "show" : "";
  }

  function status(text, modified) {
    var msg = { action: "status", message: text };
    if (modified !== undefined) { msg.modified = modified; }
    post(msg);
  }

  // The draw.io editor inside the frame, for Save from AWS Kit's own Done button. The
  // frame is served from the same origin, so this works without any extra protocol.
  function editor() {
    try {
      var w = frame.contentWindow;
      return w && w.awskitUi ? w.awskitUi : null;
    } catch (e) {
      return null;
    }
  }

  function save(xml, exit) {
    status("Saving...");
    return call("save", xml).then(function () {
      status("Saved to AWS Kit", false);
      if (exit) { leave(true); }
      return true;
    }).catch(function (e) {
      status("Couldn't save: " + e.message);
      post({ action: "dialog", title: "Couldn't save", message: String(e.message), button: "OK" });
      // So AWS Kit doesn't close the editor and lose the changes still in it.
      call("event", { event: "save-failed", error: String(e.message) }).catch(function () { });
      return false;
    });
  }

  function leave(saved) {
    if (state.closing) { return; }
    state.closing = true;
    call("exit", { saved: !!saved }).catch(function () { }).then(function () {
      note("Done. You can close this window.");
      try { window.close(); } catch (e) { /* not opened by a script */ }
    });
  }

  window.addEventListener("message", function (evt) {
    if (evt.source !== frame.contentWindow || evt.origin !== origin) { return; }
    var msg;
    try { msg = typeof evt.data === "string" ? JSON.parse(evt.data) : evt.data; } catch (e) { return; }
    if (!msg || !msg.event) { return; }
    if (msg.event === "configure") {
      call("config").then(function (r) { return r.json(); }).then(function (cfg) {
        post({ action: "configure", config: cfg });
      });
    } else if (msg.event === "init") {
      call("file").then(function (r) { return r.text(); }).then(function (xml) {
        post({ action: "load", xml: xml, autosave: 0, title: document.title.split(" - ")[0],
               modified: "unsavedChanges", noSaveBtn: 0, saveAndExit: 1, noExitBtn: 0 });
      }).catch(function (e) {
        note("Couldn't load the diagram from AWS Kit: " + e.message);
      });
    } else if (msg.event === "load") {
      state.loaded = true;
      call("event", { event: "loaded", page: page }).catch(function () { });
      loadLibrary();
    } else if (msg.event === "save") {
      save(msg.xml, !!msg.exit);
    } else if (msg.event === "exit") {
      leave(false);
    }
  });

  // The AWS Kit Designer shapes, when AWS Kit has a library for this file. draw.io won't
  // fetch libraries by URL while it's offline, so it's handed over directly.
  function loadLibrary() {
    var ui = editor();
    if (!ui || state.library) { return; }
    state.library = true;
    call("library.xml").then(function (r) { return r.text(); }).then(function (xml) {
      var w = frame.contentWindow;
      ui.loadLibrary(new w.LocalLibrary(ui, xml, "AWS Kit Designer"), true);
    }).catch(function () { /* no library for this file */ });
  }

  // AWS Kit's Done and Cancel buttons call these.
  window.awskitSave = function (exit) {
    var ui = editor();
    if (!ui) { return "no-editor"; }
    var xml = ui.getFileData(true);
    save(xml, exit);
    return "saving";
  };
  window.awskitExit = function () { leave(false); return "ok"; };
  window.awskitModified = function () {
    var ui = editor();
    return ui && ui.editor ? !!ui.editor.modified : false;
  };

  // A heartbeat, so AWS Kit can tell when a browser window was closed without Exit.
  state.timer = setInterval(function () {
    if (!state.closing) { call("alive", { loaded: state.loaded, page: page }).catch(function () { }); }
  }, 5000);
  // A hidden window's timers are slowed down, so say hello as soon as it's shown again.
  document.addEventListener("visibilitychange", function () {
    if (!document.hidden && !state.closing) {
      call("alive", { loaded: state.loaded, page: page }).catch(function () { });
    }
  });
  window.addEventListener("pagehide", function () {
    if (!state.closing && navigator.sendBeacon) {
      navigator.sendBeacon(base + "closed", JSON.stringify({ page: page }));
    }
  });
})();

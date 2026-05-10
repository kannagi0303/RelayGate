function createRelayGateUserScriptRuntime(config) {
  const listeners = new Map();
  const prefix = String(config && config.storagePrefix || "__RelayGate_UserScript__:");

  function fullKey(key) {
    return prefix + String(key);
  }

  function warn(name) {
    console.warn("[RelayGate User Script] " + name + " is not fully supported in v1.");
  }

  function parseValue(raw, defaultValue) {
    if (raw == null) {
      return defaultValue;
    }
    try {
      return JSON.parse(raw);
    } catch (_) {
      return raw;
    }
  }

  function notify(key, oldValue, newValue) {
    const items = listeners.get(String(key)) || [];
    items.forEach(function (item) {
      try {
        item.callback(String(key), oldValue, newValue, false);
      } catch (error) {
        console.warn(error);
      }
    });
  }

  const api = {};
  api.addStyle = function (css) {
    const style = document.createElement("style");
    style.textContent = String(css || "");
    (document.head || document.documentElement || document.body).appendChild(style);
    return style;
  };
  api.getValueSync = function (key, defaultValue) {
    return parseValue(localStorage.getItem(fullKey(key)), defaultValue);
  };
  api.setValueSync = function (key, value) {
    const oldValue = api.getValueSync(key);
    localStorage.setItem(fullKey(key), JSON.stringify(value));
    notify(key, oldValue, value);
  };
  api.deleteValueSync = function (key) {
    const oldValue = api.getValueSync(key);
    localStorage.removeItem(fullKey(key));
    notify(key, oldValue, undefined);
  };
  api.listValuesSync = function () {
    const keys = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key && key.indexOf(prefix) === 0) {
        keys.push(key.slice(prefix.length));
      }
    }
    return keys;
  };
  api.getValue = function (key, defaultValue) {
    return Promise.resolve(api.getValueSync(key, defaultValue));
  };
  api.setValue = function (key, value) {
    api.setValueSync(key, value);
    return Promise.resolve();
  };
  api.deleteValue = function (key) {
    api.deleteValueSync(key);
    return Promise.resolve();
  };
  api.listValues = function () {
    return Promise.resolve(api.listValuesSync());
  };
  api.addValueChangeListener = function (key, callback) {
    const id = Math.random().toString(36).slice(2);
    const list = listeners.get(String(key)) || [];
    list.push({ id: id, callback: callback });
    listeners.set(String(key), list);
    return id;
  };
  api.removeValueChangeListener = function (id) {
    for (const entry of listeners.entries()) {
      const next = entry[1].filter(function (item) {
        return item.id !== id;
      });
      if (next.length !== entry[1].length) {
        listeners.set(entry[0], next);
        return true;
      }
    }
    return false;
  };
  api.openInTab = function (url) {
    warn("GM_openInTab");
    return window.open(url, "_blank");
  };
  api.xmlhttpRequest = function (details) {
    warn("GM_xmlhttpRequest");
    if (details && typeof details.onerror === "function") {
      details.onerror({ error: "unsupported" });
    }
    return { abort: function () {} };
  };
  return api;
}

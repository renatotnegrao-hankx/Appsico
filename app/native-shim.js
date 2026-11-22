/* Ponte com o app Android do Appsico (substitui o Capacitor). No navegador não faz nada. */
(function () {
  var N = window.AppsicoNative;
  if (!N) return;
  var listeners = {};
  window.__appsicoEvent = function (n) { (listeners[n] || []).forEach(function (f) { try { f(); } catch (e) {} }); };
  var S = function (v) { return v == null ? '' : String(v); };
  var name = function (u) { return S(u).split('/').pop(); };
  var P = {
    Filesystem: {
      readFile: async function (o) { var r = N.readFile(S(o.path), S(o.directory || 'DATA')); if (r == null) throw new Error('Arquivo não encontrado'); return { data: r }; },
      writeFile: async function (o) { var u = N.writeFile(S(o.path), S(o.data), S(o.directory || 'DATA'), o.encoding ? '0' : '1'); if (u == null) throw new Error('Falha ao gravar'); return { uri: u }; },
      deleteFile: async function (o) { N.deleteFile(S(o.path), S(o.directory || 'DATA')); }
    },
    Share: {
      share: async function (o) { var f = (o.files && o.files[0]) || o.url || ''; N.share(S(o.dialogTitle || o.title || 'Compartilhar'), S(o.text), name(f), S(o.package)); return {}; }
    },
    App: {
      addListener: function (n, f) { (listeners[n] = listeners[n] || []).push(f); return { remove: function () {} }; },
      minimizeApp: async function () { N.minimize(); },
      exitApp: async function () { N.minimize(); }
    },
    AppsicoKeystore: {
      set: async function (o) { if (N.ksSet(S(o.key), S(o.value)) == null) throw new Error('Keystore indisponível'); },
      get: async function (o) { return { value: N.ksGet(S(o.key)) }; }
    }
  };
  window.AppsicoPrint = function (fileName, job) { N.printPdf(S(fileName), S(job || 'Appsico')); };
  window.Capacitor = { isNativePlatform: function () { return true; }, getPlatform: function () { return 'android'; }, registerPlugin: function (n) { return P[n]; } };
})();

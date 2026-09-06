// vida panel i18n injector (zh/en) - SPA 构建产物注入模板
// 用法: 放到 web-dist/assets/i18n.js, index.html </body> 前加
//   <script src="./assets/i18n.js"></script>
// 词条表 DICT: 原文 -> {en: 英文, zh: 中文}; 默认语言 'en' (把外语原文翻成英文)
(function(){
  var DICT = { /* 词条表: "Original": {"en": "English", "zh": "中文"} */ };
  var STORE = 'vida_lang';
  var lang = localStorage.getItem(STORE) || 'en';
  function translateText(text){
    var out = text, applied = false;
    var keys = Object.keys(DICT).sort(function(a,b){return b.length-a.length;}); // 长词优先
    for (var i=0;i<keys.length;i++){
      var key = keys[i], entry = DICT[key], target = entry[lang];
      if (!target || target === key) continue;
      var lower = out.toLowerCase(), kl = key.toLowerCase();
      var idx = lower.indexOf(kl);
      while (idx !== -1){
        // 词边界只挡字母, 不挡数字: "Dispositivos (3)" -> "设备 (3)"
        var before = idx>0?lower[idx-1]:'';
        var after = idx+key.length<lower.length?lower[idx+key.length]:'';
        if (!/[a-z]/.test(before) && !/[a-z]/.test(after)){
          out = out.substring(0,idx)+target+out.substring(idx+key.length);
          applied = true;
          lower = out.toLowerCase();
          idx = lower.indexOf(kl, idx+target.length);
        } else {
          idx = lower.indexOf(kl, idx+key.length);
        }
      }
    }
    return applied ? out : text;
  }
  function walk(node){
    if (!node || node.nodeType === 8) return;
    if (node.nodeType === 3){
      var v = node.nodeValue;
      if (v && v.trim()){
        var t = translateText(v);
        if (t !== v) node.nodeValue = t;
      }
      return;
    }
    if (node.nodeType !== 1) return;
    if (node.hasAttribute && (node.hasAttribute('data-i18n-skip') || node.tagName === 'SCRIPT' || node.tagName === 'STYLE' || node.tagName === 'TEXTAREA')) return;
    var children = Array.prototype.slice.call(node.childNodes);
    for (var i=0;i<children.length;i++) walk(children[i]);
  }
  function apply(){
    if (!document.body) return;
    walk(document.body);
    var btn = document.getElementById('vida-lang-btn');
    if (btn) btn.textContent = (lang === 'zh') ? 'EN' : '中文';
  }
  function init(){
    var btn = document.createElement('div');
    btn.id = 'vida-lang-btn';
    btn.setAttribute('data-i18n-skip','1');
    btn.style.cssText = 'position:fixed;right:16px;bottom:16px;z-index:999999;background:rgba(30,41,59,.92);color:#fff;border:1px solid rgba(255,255,255,.25);border-radius:9999px;padding:8px 18px;font:600 14px/1 system-ui,sans-serif;cursor:pointer;box-shadow:0 4px 16px rgba(0,0,0,.35);user-select:none;letter-spacing:.5px;';
    btn.textContent = (lang === 'zh') ? 'EN' : '中文';
    btn.addEventListener('click', function(){
      lang = (lang === 'zh') ? 'en' : 'zh';
      localStorage.setItem(STORE, lang);
      apply();
    });
    (document.body || document.documentElement).appendChild(btn);
    apply();
    // 监听 React 动态渲染
    var t = null;
    new MutationObserver(function(){
      clearTimeout(t);
      t = setTimeout(function(){ apply(); }, 250);
    }).observe(document.body, {childList:true, subtree:true, characterData:true});
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();

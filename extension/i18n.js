// English source strings are fallbacks; translations live only in _locales.
export const languages=['en','ru','de','fr','es','pt_BR','zh_CN','ja','ar','hi'];
export function messageKey(text) {
  let hash=2166136261;
  for(const char of text)hash=Math.imul(hash^char.charCodeAt(0),16777619)>>>0;
  return 'm_'+hash.toString(16);
}
const api=globalThis.browser??globalThis.chrome;
const extension=!!api?.runtime?.id;
const preferred=typeof navigator==='undefined'?['en']:(navigator.languages??[navigator.language]);
export const locale=preferred.map(value=>{
  const language=value.replace('-','_');
  return languages.find(candidate=>candidate.toLowerCase()===language.toLowerCase())??languages.find(candidate=>candidate.split('_')[0]===language.split('_')[0]);
}).find(Boolean)??'en';
let messages={};
if(typeof document!=='undefined'&&locale!=='en') {
  try {messages=await (await fetch(new URL(`_locales/${locale}/messages.json`,import.meta.url))).json();}catch{/* English fallback remains available offline. */}
}
export function t(english,values={}) {
  const key=messageKey(english);
  const translated=messages[key]?.message||(extension?api.i18n?.getMessage(key):'')||english;
  return translated.replace(/\{(\w+)\}/g,(match,name)=>Object.hasOwn(values,name)?String(values[name]):match);
}
export function translatePage() {
  document.documentElement.lang=locale.replace('_','-');document.documentElement.dir=locale==='ar'?'rtl':'ltr';
  for(const node of document.querySelectorAll('[data-i18n]'))node.textContent=t(node.dataset.i18n);
  for(const attribute of ['placeholder','aria-label','title'])for(const node of document.querySelectorAll(`[data-i18n-${attribute}]`))node.setAttribute(attribute,t(node.getAttribute(`data-i18n-${attribute}`)));
}

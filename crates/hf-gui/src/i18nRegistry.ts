// Dictionaries that arrive with a lazily loaded view instead of the initial
// bundle. A view's dictionary module registers itself when it is evaluated,
// which is before any component of that view renders.

type Dict = Record<string, string>;

export const lazyDictionaries: { en: Dict; zh: Dict } = { en: {}, zh: {} };

export function registerDictionary(en: Dict, zh: Dict): void {
  Object.assign(lazyDictionaries.en, en);
  Object.assign(lazyDictionaries.zh, zh);
}

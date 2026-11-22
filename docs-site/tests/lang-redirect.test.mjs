// Tests for the docs-site browser-language auto-redirect.
//
// Two layers:
//   1. Behaviour: the shipped script source (src/public/lang-redirect.js) is
//      executed in a node:vm sandbox with stubbed navigator/location/
//      localStorage/document, and the redirect decision is asserted for the
//      matrix of locale, path and stored choice.
//   2. Artifact: the vitepress dist output really references the script and
//      the script file itself was copied to the dist root.

import test from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import vm from 'node:vm'

const here = dirname(fileURLToPath(import.meta.url))
const siteRoot = join(here, '..')
const scriptPath = join(siteRoot, 'src', 'public', 'lang-redirect.js')
const distRoot = join(siteRoot, 'src', '.vitepress', 'dist')

const EN_HOME = '/syncbond/'
const ZH_HOME = '/syncbond/zh/'
const STORAGE_KEY = 'sbLang'

/**
 * Run the real script source against stubbed browser globals.
 *
 * @param {{pathname: string, languages?: string[], language?: string|null,
 *          stored?: Record<string,string>, storageThrows?: boolean}} scenario
 * @returns {{replaced: string|null, stored: Record<string,string>,
 *            click: (el: unknown) => void}}
 */
function runScenario(scenario) {
  const { pathname, languages = [], language = null, stored = {}, storageThrows = false } = scenario
  const replaced = { called: false, url: null }
  const store = { ...stored }
  const listeners = []

  const localStorage = storageThrows
    ? {
        getItem() {
          throw new Error('storage blocked')
        },
        setItem() {
          throw new Error('storage blocked')
        }
      }
    : {
        getItem(key) {
          return key in store ? store[key] : null
        },
        setItem(key, value) {
          store[key] = String(value)
        }
      }

  // Element stub: walking parentNode must reach the anchor's tagName/attrs.
  function anchor(href) {
    return {
      nodeType: 1,
      tagName: 'A',
      getAttribute(name) {
        return name === 'href' ? href : null
      },
      parentNode: null
    }
  }

  const sandbox = {
    navigator: { languages, language },
    location: {
      pathname,
      replace(url) {
        replaced.called = true
        replaced.url = url
      }
    },
    localStorage,
    document: {
      addEventListener(type, handler) {
        if (type === 'click') listeners.push(handler)
      }
    }
  }
  vm.createContext(sandbox)
  vm.runInContext(readFileSync(scriptPath, 'utf8'), sandbox, { filename: scriptPath })

  assert.equal(listeners.length, 1, 'the click listener must be registered exactly once')

  return {
    replaced: replaced.called ? replaced.url : null,
    stored: store,
    // Fire the capture-phase listener with a fake anchor, as the browser
    // would when a locale-root link is clicked.
    click(href) {
      const el = anchor(href)
      listeners[0]({ target: el })
    }
  }
}

test('a zh browser on the English home is redirected to the Chinese home', () => {
  const run = runScenario({ pathname: EN_HOME, languages: ['zh-CN', 'en-US'] })
  assert.equal(run.replaced, ZH_HOME)
})

test('an en browser on the Chinese home is redirected to the English home', () => {
  const run = runScenario({ pathname: ZH_HOME, language: 'en-US' })
  assert.equal(run.replaced, EN_HOME)
})

test('a zh browser with an explicit en choice stays on the English home', () => {
  const run = runScenario({ pathname: EN_HOME, languages: ['zh-CN'], stored: { [STORAGE_KEY]: 'en' } })
  assert.equal(run.replaced, null)
})

test('an en browser with an explicit zh choice stays on the Chinese home', () => {
  const run = runScenario({ pathname: ZH_HOME, languages: ['en-US'], stored: { [STORAGE_KEY]: 'zh' } })
  assert.equal(run.replaced, null)
})

test('an explicit en choice wins even on the Chinese home', () => {
  const run = runScenario({ pathname: ZH_HOME, languages: ['zh-CN'], stored: { [STORAGE_KEY]: 'en' } })
  assert.equal(run.replaced, EN_HOME)
})

test('deep links are never redirected', () => {
  for (const [pathname, languages, language] of [
    ['/syncbond/design/merge', ['zh-CN'], null],
    ['/syncbond/zh/design/merge', [], 'en-US'],
    ['/syncbond/deploy', ['zh-CN'], null],
    ['/syncbond/zh/deploy', [], 'en-US'],
    ['/syncbond/requirements', ['zh-CN'], null]
  ]) {
    const run = runScenario({ pathname, languages, language })
    assert.equal(run.replaced, null, `${pathname} must not redirect`)
  }
})

test('the index.html fallback of the English home is treated as a home', () => {
  const run = runScenario({ pathname: '/syncbond/index.html', languages: ['zh-CN'] })
  assert.equal(run.replaced, ZH_HOME)
})

test('the bare and index.html forms of each home are recognized', () => {
  const cases = [
    ['/syncbond', 'zh-CN', ZH_HOME],
    ['/syncbond/index.html', 'zh-CN', ZH_HOME],
    ['/syncbond/zh', 'en-US', EN_HOME],
    ['/syncbond/zh/index.html', 'en-US', EN_HOME]
  ]
  for (const [pathname, language, expected] of cases) {
    const run = runScenario({ pathname, language })
    assert.equal(run.replaced, expected, `${pathname} + ${language} should redirect to ${expected}`)
  }
})

test('the primary language decides, not a secondary one', () => {
  // navigator.languages[0] wins. An English-first list must not be pulled
  // to the Chinese pages even though a zh entry appears later, and vice
  // versa: the primary language is what the redirect follows.
  const enFirst = runScenario({ pathname: ZH_HOME, languages: ['en-US', 'zh-CN'] })
  assert.equal(enFirst.replaced, EN_HOME)
  const zhFirst = runScenario({ pathname: EN_HOME, languages: ['zh-CN', 'en-US'] })
  assert.equal(zhFirst.replaced, ZH_HOME)
})

test('a language tag is detected without a region subtag', () => {
  const run = runScenario({ pathname: EN_HOME, language: 'zh' })
  assert.equal(run.replaced, ZH_HOME)
  const regionVariant = runScenario({ pathname: EN_HOME, language: 'zh-Hant' })
  assert.equal(regionVariant.replaced, ZH_HOME)
})

test('no language signal means no redirect', () => {
  const run = runScenario({ pathname: ZH_HOME })
  assert.equal(run.replaced, null)
  const empty = runScenario({ pathname: EN_HOME, languages: [] })
  assert.equal(empty.replaced, null)
})

test('blocked storage degrades to detection without breaking', () => {
  const run = runScenario({ pathname: EN_HOME, languages: ['zh-CN'], storageThrows: true })
  assert.equal(run.replaced, ZH_HOME)
  const atZh = runScenario({ pathname: ZH_HOME, languages: ['zh-CN'], storageThrows: true })
  assert.equal(atZh.replaced, null)
})

test('a click on the language switcher records the choice', () => {
  const run = runScenario({ pathname: ZH_HOME, languages: ['zh-CN'] })
  assert.equal(run.replaced, null) // already home
  run.click(ZH_HOME)
  assert.equal(run.stored[STORAGE_KEY], 'zh')
  run.click(EN_HOME)
  assert.equal(run.stored[STORAGE_KEY], 'en')
})

test('a click on a non-locale link records nothing', () => {
  const run = runScenario({ pathname: EN_HOME, languages: ['en-US'] })
  run.click('/syncbond/design/merge')
  assert.equal(run.stored[STORAGE_KEY], undefined)
})

test('the built dist references the script and ships the file', () => {
  if (!existsSync(distRoot)) {
    test.skip('dist not built (run `pnpm docs:build` first)')
    return
  }
  const scriptTag = readFileSync(join(distRoot, 'index.html'), 'utf8')
  assert.match(scriptTag, /<script src="\/syncbond\/lang-redirect\.js"/)
  const zhIndex = readFileSync(join(distRoot, 'zh', 'index.html'), 'utf8')
  assert.match(zhIndex, /<script src="\/syncbond\/lang-redirect\.js"/)
  assert.ok(existsSync(join(distRoot, 'lang-redirect.js')), 'lang-redirect.js must be copied to the dist root')
})

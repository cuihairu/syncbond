#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, extname, join, normalize, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const distDir = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../docs-site/src/.vitepress/dist'
)

if (!existsSync(distDir)) {
  console.error(`Docs build output not found: ${distDir}`)
  process.exit(1)
}

const htmlFiles = []

function collectHtmlFiles(currentDir) {
  for (const entry of readdirSync(currentDir)) {
    const entryPath = join(currentDir, entry)
    if (statSync(entryPath).isDirectory()) {
      collectHtmlFiles(entryPath)
    } else if (extname(entry) === '.html') {
      htmlFiles.push(entryPath)
    }
  }
}

function targetExists(rawTarget) {
  // base=/syncbond/: 站内链接带前缀,解析 dist 路径时先剥掉
  const target = (rawTarget.replace(/^\/syncbond(?=\/|$)/, '') || '/').split('#')[0]
  if (!target || target === '/' || target === '/zh/') return true
  const decodedTarget = decodeURIComponent(target)
  const normalizedTarget = normalize(decodedTarget).replace(/^([.][.][/\\])+/, '').replace(/^[/\\]+/, '')
  const absoluteTarget = join(distDir, normalizedTarget)
  if (!absoluteTarget.startsWith(distDir)) return false
  if (existsSync(absoluteTarget)) return true
  if (extname(absoluteTarget)) return false
  return (
    existsSync(`${absoluteTarget}.html`) ||
    existsSync(join(absoluteTarget, 'index.html'))
  )
}

collectHtmlFiles(distDir)

const missingLinks = []
const internalLinkPattern = /(?:href|src)="([^"]+)"/g

for (const file of htmlFiles) {
  // 剥掉站点导航壳(vitepress 会把各语言菜单都预渲染进页面,属生成物非内容链接,
  // 由 vitepress 自带 dead-links 检查兜底);正文与侧栏链接照常校验
  const html = readFileSync(file, 'utf8')
    .replace(/<header[\s\S]*?<\/header>/g, '')
    .replace(/<nav[\s\S]*?<\/nav>/g, '')
  for (const match of html.matchAll(internalLinkPattern)) {
    const target = match[1]
    if (target.startsWith('//') || /^[a-z][a-z\d+.-]*:/i.test(target)) continue
    if (target.startsWith('#')) continue
    if (!target.startsWith('/')) continue
  if (!target.startsWith('/syncbond/') && !['/', '/zh/', '/zh'].includes(target)) continue
    if (!targetExists(target)) {
      missingLinks.push({ file, target })
    }
  }
}

if (missingLinks.length > 0) {
  console.error('Missing internal links:')
  for (const { file, target } of missingLinks) {
    console.error(`  ${target} in ${file}`)
  }
  process.exit(1)
}

console.log(`Verified internal links in ${htmlFiles.length} HTML files.`)

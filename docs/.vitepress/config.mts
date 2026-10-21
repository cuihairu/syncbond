import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'SyncBond',
  description:
    'Accountless, embeddable, end-to-end encrypted device pairing and data synchronization infrastructure.',
  // Light theme only, per project decision.
  appearance: false,
  // Static assets served from docs/public (icon.svg copy of assets/icon.svg).
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/icon.svg' }]],
  ignoreDeadLinks: false,
  locales: {
    root: {
      label: 'English',
      themeConfig: {
        nav: [
          { text: 'Home', link: '/' },
          { text: 'Requirements', link: '/requirements' },
          {
            text: 'Design',
            items: [
              { text: 'Protocol (v1)', link: '/design/PROTOCOL' },
              { text: 'Merge strategies', link: '/design/merge' },
              { text: 'Language decision', link: '/design/language' }
            ]
          },
          { text: 'Research', link: '/research/survey-2026-10-21' },
          {
            text: 'GitHub',
            link: 'https://github.com/cuihairu/syncbond'
          }
        ],
        sidebar: [
          {
            text: 'Getting started',
            items: [{ text: 'Overview', link: '/' }]
          },
          {
            text: 'Requirements',
            items: [{ text: 'Baseline (R1–R11)', link: '/requirements' }]
          },
          {
            text: 'Design',
            items: [
              { text: 'Protocol specification (v1)', link: '/design/PROTOCOL' },
              { text: 'Merge strategies & tombstones', link: '/design/merge' },
              { text: 'Language decision: Rust core', link: '/design/language' }
            ]
          },
          {
            text: 'Research',
            items: [
              {
                text: 'Landscape survey (2026-10-21)',
                link: '/research/survey-2026-10-21'
              }
            ]
          }
        ],
        search: {
          provider: 'local'
        }
      }
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      description:
        '无账号、可嵌入、端到端加密的设备配对与数据同步基础设施。',
      themeConfig: {
        nav: [
          { text: '首页', link: '/zh/' },
          { text: '需求', link: '/zh/requirements' },
          {
            text: '设计',
            items: [
              { text: '协议（v1）', link: '/design/PROTOCOL' },
              { text: '合并策略', link: '/design/merge' },
              { text: '语言决策', link: '/design/language' }
            ]
          },
          { text: '调研', link: '/zh/research/survey-2026-10-21' },
          {
            text: 'GitHub',
            link: 'https://github.com/cuihairu/syncbond'
          }
        ],
        sidebar: [
          {
            text: '开始',
            items: [{ text: '概述', link: '/zh/' }]
          },
          {
            text: '需求',
            items: [{ text: '需求基线（R1–R11）', link: '/zh/requirements' }]
          },
          {
            text: '设计',
            items: [
              { text: '协议规范 v1（英文）', link: '/design/PROTOCOL' },
              { text: '合并策略与墓碑（英文）', link: '/design/merge' },
              { text: '语言决策：Rust core（英文）', link: '/design/language' }
            ]
          },
          {
            text: '调研',
            items: [
              {
                text: '现状调研（2026-10-21）',
                link: '/zh/research/survey-2026-10-21'
              }
            ]
          }
        ],
        search: {
          provider: 'local'
        }
      }
    }
  }
})

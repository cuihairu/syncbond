import { defineConfig } from 'vitepress'
import type { DefaultTheme } from 'vitepress'

const githubIcon =
  'M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z'

const sharedConfig = {
  title: 'SyncBond',
  description:
    'Accountless, embeddable, end-to-end encrypted device pairing and data synchronization infrastructure.',
  appearance: false,
  cleanUrls: true,
  ignoreDeadLinks: false,
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/icon.svg' }]],
  themeConfig: {
    logo: { src: '/icon.svg', width: 64, height: 64 },
    externalLinkIcon: true,
    socialLinks: [{ icon: { svg: githubIcon }, link: 'https://github.com/cuihairu/syncbond', ariaLabel: 'GitHub' }]
  }
} satisfies DefaultTheme.Config

export default defineConfig({
  ...sharedConfig,
  locales: {
    root: {
      label: 'English',
      themeConfig: {
        ...sharedConfig.themeConfig,
        nav: [
          { text: 'Home', link: '/', activeMatch: '^/$|^/index' },
          { text: 'Requirements', link: '/requirements', activeMatch: '^/requirements/' },
          {
            text: 'Design',
            items: [
              { text: 'Protocol (v1)', link: '/design/PROTOCOL' },
              { text: 'Merge strategies', link: '/design/merge' },
              { text: 'Language decision', link: '/design/language' }
            ]
          },
          { text: 'Research', link: '/research/survey-2026-10-21', activeMatch: '^/research/' },
          { component: 'GitHub' }
        ],
        sidebar: {
          '/': [
            { text: 'Overview', link: '/' },
            { text: 'Requirements', items: [{ text: 'Baseline (R1–R11)', link: '/requirements' }] },
            {
              text: 'Design',
              items: [
                { text: 'Protocol specification (v1)', link: '/design/PROTOCOL' },
                { text: 'Merge strategies & tombstones', link: '/design/merge' },
                { text: 'Language decision: Rust core', link: '/design/language' }
              ]
            },
            { text: 'Research', items: [{ text: 'Landscape survey (2026-10-21)', link: '/research/survey-2026-10-21' }] }
          ]
        },
        search: { provider: 'local', options: { localeTranslations: { buttonText: 'Search docs', buttonAriaLabel: 'Search docs' } } },
        outline: { level: [2, 3], label: 'On this page' },
        docFooter: { prev: 'Previous', next: 'Next' },
        lastUpdated: { text: 'Updated at', formatOptions: { dateStyle: 'medium', timeStyle: 'medium' } }
      }
    },
    zh: {
      label: '简体中文',
      lang: 'zh-CN',
      description: '无账号、可嵌入、端到端加密的设备配对与数据同步基础设施。',
      themeConfig: {
        ...sharedConfig.themeConfig,
        nav: [
          { text: '首页', link: '/zh/', activeMatch: '^/zh/?$' },
          { text: '需求', link: '/zh/requirements', activeMatch: '^/zh/requirements/' },
          {
            text: '设计',
            items: [
              { text: '协议（v1）', link: '/design/PROTOCOL' },
              { text: '合并策略', link: '/design/merge' },
              { text: '语言决策', link: '/design/language' }
            ]
          },
          { text: '调研', link: '/zh/research/survey-2026-10-21', activeMatch: '^/zh/research/' },
          { component: 'GitHub' }
        ],
        sidebar: {
          '/zh/': [
            { text: '概述', link: '/zh/' },
            { text: '需求', items: [{ text: '需求基线（R1–R11）', link: '/zh/requirements' }] },
            {
              text: '设计',
              items: [
                { text: '协议规范 v1（English）', link: '/design/PROTOCOL' },
                { text: '合并策略与墓碑（English）', link: '/design/merge' },
                { text: '语言决策：Rust core（English）', link: '/design/language' }
              ]
            },
            { text: '调研', items: [{ text: '现状调研（2026-10-21）', link: '/zh/research/survey-2026-10-21' }] }
          ]
        },
        search: {
          provider: 'local',
          options: {
            translations: {
              button: { buttonText: '搜索文档', buttonAriaLabel: '搜索文档' },
              modal: {
                noResultsText: '未找到结果',
                resetButtonTitle: '清除查询条件',
                footer: { selectText: '选择', navigateText: '切换', closeText: '关闭' }
              }
            }
          }
        },
        outline: { level: [2, 3], label: '本页内容' },
        docFooter: { prev: '上一页', next: '下一页' },
        lastUpdated: { text: '更新时间', formatOptions: { dateStyle: 'medium', timeStyle: 'medium' } }
      }
    }
  },
  markdown: { theme: 'github-light' }
})

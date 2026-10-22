import { defineConfig } from 'vitepress'
import type { DefaultTheme } from 'vitepress'

const sharedConfig = {
  base: '/syncbond/',
  title: 'SyncBond',
  description:
    'Accountless, embeddable, end-to-end encrypted device pairing and data synchronization infrastructure.',
  appearance: false,
  cleanUrls: true,
  ignoreDeadLinks: false,
  head: [['link', { rel: 'icon', type: 'image/svg+xml', href: '/syncbond/icon.svg' }]],
  themeConfig: {
    logo: { src: '/icon.svg', width: 64, height: 64 },
    externalLinkIcon: true,
    // GitHub 入口只留导航里的自定义组件(双语 nav 已各有一项),不再叠加 socialLinks 以免双图标
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
              { text: '协议（v1）', link: '/zh/design/PROTOCOL' },
              { text: '合并策略', link: '/zh/design/merge' },
              { text: '语言决策', link: '/zh/design/language' }
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
                { text: '协议规范 v1', link: '/zh/design/PROTOCOL' },
                { text: '合并策略与墓碑', link: '/zh/design/merge' },
                { text: '语言决策：Rust core', link: '/zh/design/language' }
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

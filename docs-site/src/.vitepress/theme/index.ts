import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import DocHeader from './DocHeader.vue'
import GitHubIcon from './GitHubIcon.vue'
import LanguageSwitch from './LanguageSwitch.vue'
import './docs.css'

export default {
  extends: DefaultTheme,
  Layout: DocHeader,
  enhanceApp({ app }) {
    app.component('GitHub', GitHubIcon)
  }
} satisfies Theme

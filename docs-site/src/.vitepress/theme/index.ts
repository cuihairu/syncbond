import type { Theme } from 'vitepress'
import DefaultTheme from 'vitepress/theme'
import GitHubIcon from './GitHubIcon.vue'
import './docs.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('GitHub', GitHubIcon)
  }
} satisfies Theme

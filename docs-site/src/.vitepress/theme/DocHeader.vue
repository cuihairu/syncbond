<script setup>
import DefaultTheme from 'vitepress/theme'

const Layout = DefaultTheme.Layout
</script>

<template>
  <Layout>
    <template #nav-bar-content-after>
      <LanguageSwitch />
    </template>
  </Layout>
</template>

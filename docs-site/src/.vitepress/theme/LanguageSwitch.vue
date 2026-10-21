<template>
  <div class="language-switch" role="group" aria-label="Language">
    <a class="language-link" :class="{ active: locale === 'root' }" href="/" :aria-current="locale === 'root' ? 'page' : undefined">EN</a>
    <a class="language-link" :class="{ active: locale === 'zh' }" href="/zh/" :aria-current="locale === 'zh' ? 'page' : undefined">中文</a>
  </div>
</template>

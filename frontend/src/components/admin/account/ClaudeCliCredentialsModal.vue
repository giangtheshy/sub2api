<template>
  <BaseDialog
    :show="show"
    :title="t('admin.accounts.claudeCli.title')"
    width="normal"
    close-on-click-outside
    @close="$emit('close')"
  >
    <div class="space-y-4">
      <p class="text-sm text-gray-600 dark:text-dark-300">
        {{ t('admin.accounts.claudeCli.intro', { name: account?.name ?? '' }) }}
      </p>

      <div v-if="loading" class="py-8 text-center text-sm text-gray-500 dark:text-dark-400">
        {{ t('common.loading') }}
      </div>

      <div
        v-else-if="errorMessage"
        class="rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-600 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400"
      >
        {{ errorMessage }}
      </div>

      <template v-else-if="result">
        <!-- Rotation is the one thing an operator must read before pasting this
             file, so it is a banner rather than a footnote. -->
        <div
          v-for="warning in translatedWarnings"
          :key="warning.code"
          class="rounded-lg border p-3 text-xs"
          :class="warning.severe
            ? 'border-amber-300 bg-amber-50 text-amber-700 dark:border-amber-700 dark:bg-amber-900/20 dark:text-amber-300'
            : 'border-gray-200 bg-gray-50 text-gray-600 dark:border-dark-600 dark:bg-dark-800 dark:text-dark-300'"
        >
          {{ warning.text }}
        </div>

        <div v-if="lifetimeLabel" class="text-xs text-gray-500 dark:text-dark-400">
          {{ lifetimeLabel }}
        </div>

        <label class="flex cursor-pointer items-start gap-2 rounded-lg border border-gray-200 p-3 dark:border-dark-600">
          <input
            v-model="includeRefreshToken"
            type="checkbox"
            class="mt-0.5 shrink-0"
          />
          <span class="text-xs">
            <span class="font-medium text-gray-700 dark:text-dark-200">
              {{ t('admin.accounts.claudeCli.includeRefreshToken') }}
            </span>
            <span class="mt-0.5 block text-gray-500 dark:text-dark-400">
              {{ t('admin.accounts.claudeCli.includeRefreshTokenHint') }}
            </span>
          </span>
        </label>

        <div>
          <div class="mb-1 flex items-end justify-between gap-2">
            <label class="input-label mb-0">{{ t('admin.accounts.claudeCli.fileLabel') }}</label>
            <code class="text-xs text-gray-500 dark:text-dark-400">{{ result.file_name }}</code>
          </div>
          <pre
            class="max-h-64 overflow-auto rounded-lg border border-gray-200 bg-gray-50 p-3 font-mono text-xs leading-relaxed text-gray-800 dark:border-dark-600 dark:bg-dark-800 dark:text-dark-200"
          >{{ fileContent }}</pre>
        </div>

        <div>
          <label class="input-label">{{ t('admin.accounts.claudeCli.pathLabel') }}</label>
          <div class="space-y-1 font-mono text-xs text-gray-600 dark:text-dark-300">
            <div><span class="text-gray-400 dark:text-dark-500">Windows</span> %USERPROFILE%\.claude\.credentials.json</div>
            <div><span class="text-gray-400 dark:text-dark-500">macOS / Linux</span> ~/.claude/.credentials.json</div>
          </div>
          <p class="mt-2 text-xs text-gray-500 dark:text-dark-400">
            {{ t('admin.accounts.claudeCli.pathHint') }}
          </p>
        </div>
      </template>
    </div>

    <template #footer>
      <div class="flex justify-end gap-3">
        <button class="btn btn-secondary" type="button" @click="$emit('close')">
          {{ t('common.close') }}
        </button>
        <button class="btn btn-secondary" type="button" :disabled="!result" @click="handleCopy">
          {{ t('admin.accounts.claudeCli.copy') }}
        </button>
        <button class="btn btn-primary" type="button" :disabled="!result" @click="handleDownload">
          {{ t('admin.accounts.claudeCli.download') }}
        </button>
      </div>
    </template>
  </BaseDialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseDialog from '@/components/common/BaseDialog.vue'
import { exportClaudeCliCredentials, type ClaudeCliCredentialsExport } from '@/api/admin/accounts'
import { useAppStore } from '@/stores/app'
import type { Account } from '@/types'

const props = defineProps<{ show: boolean; account: Account | null }>()
defineEmits(['close'])

const { t } = useI18n()
const appStore = useAppStore()

const loading = ref(false)
const errorMessage = ref('')
const result = ref<ClaudeCliCredentialsExport | null>(null)
// Default off: without a refresh token the CLI cannot rotate the credential,
// so this account stays sub2api's. Turning it on is a deliberate handover.
const includeRefreshToken = ref(false)

// Warnings that change what the operator should do, versus ones that merely
// describe the credential. Only the former earn the amber treatment.
const severeWarnings = new Set(['refresh_token_rotation', 'no_refresh_token', 'access_token_expired'])

const fileContent = computed(() =>
  result.value ? JSON.stringify(result.value.credentials, null, 2) : ''
)

const translatedWarnings = computed(() =>
  (result.value?.warnings ?? []).map(code => ({
    code,
    severe: severeWarnings.has(code),
    text: t(`admin.accounts.claudeCli.warnings.${code}`)
  }))
)

const lifetimeLabel = computed(() => {
  const seconds = result.value?.expires_in_seconds
  if (!seconds || seconds <= 0) return ''
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return t('admin.accounts.claudeCli.lifetime', { hours, minutes })
})

async function load(accountId: number) {
  loading.value = true
  errorMessage.value = ''
  result.value = null
  try {
    result.value = await exportClaudeCliCredentials(accountId, includeRefreshToken.value)
  } catch (error) {
    errorMessage.value =
      error instanceof Error ? error.message : t('admin.accounts.claudeCli.loadFailed')
  } finally {
    loading.value = false
  }
}

watch(
  () => [props.show, props.account?.id, includeRefreshToken.value] as const,
  ([visible, accountId]) => {
    if (visible && typeof accountId === 'number') {
      void load(accountId)
    }
    if (!visible) {
      // Do not keep a live OAuth token in component state after the dialog
      // closes; reopening re-fetches it. The toggle resets too, so sharing
      // the refresh token is always a fresh, deliberate choice rather than a
      // setting left on from a previous account.
      result.value = null
      errorMessage.value = ''
      includeRefreshToken.value = false
    }
  },
  { immediate: true }
)

async function handleCopy() {
  if (!fileContent.value) return
  try {
    await navigator.clipboard.writeText(fileContent.value)
    appStore.showSuccess(t('admin.accounts.claudeCli.copied'))
  } catch {
    appStore.showError(t('admin.accounts.claudeCli.copyFailed'))
  }
}

function handleDownload() {
  if (!result.value) return
  const blob = new Blob([fileContent.value], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  // A leading-dot filename is what the CLI reads, but browsers and some
  // shells hide it; "claude-credentials.json" downloads visibly and the
  // dialog states the name to rename it to.
  link.download = 'claude-credentials.json'
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}
</script>

import { defineComponent } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const {
  createAccountMock,
  importOAuthCredentialsMock,
  validateClaudeCookieMock,
} = vi.hoisted(() => ({
  createAccountMock: vi.fn(),
  importOAuthCredentialsMock: vi.fn(),
  validateClaudeCookieMock: vi.fn(),
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({
    showError: vi.fn(),
    showSuccess: vi.fn(),
    showWarning: vi.fn(),
  }),
}))

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({ isSimpleMode: true }),
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    accounts: {
      create: createAccountMock,
      probeUpstreamBilling: vi.fn(),
      checkMixedChannelRisk: vi.fn().mockResolvedValue({ has_risk: false }),
      importCodexSession: vi.fn(),
      createOpenAICodexPAT: vi.fn(),
      importOAuthCredentials: importOAuthCredentialsMock,
      validateClaudeCookie: validateClaudeCookieMock,
    },
    settings: {
      getWebSearchEmulationConfig: vi.fn().mockResolvedValue({ enabled: false, providers: [] }),
      getSettings: vi.fn().mockResolvedValue({}),
    },
    tlsFingerprintProfiles: {
      list: vi.fn().mockResolvedValue([]),
    },
  },
}))

vi.mock('@/api/admin/accounts', () => ({
  getAntigravityDefaultModelMapping: vi.fn().mockResolvedValue([]),
}))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({ t: (key: string) => key }),
  }
})

import CreateAccountModal from '../CreateAccountModal.vue'

const BaseDialogStub = defineComponent({
  name: 'BaseDialog',
  props: { show: { type: Boolean, default: false } },
  template: '<div v-if="show"><slot /><slot name="footer" /></div>',
})

const OAuthAuthorizationFlowStub = defineComponent({
  name: 'OAuthAuthorizationFlow',
  props: {
    showManualOption: Boolean,
    showImportCredentialsOption: Boolean,
    showCookieFileOption: Boolean,
    initialInputMethod: String,
  },
  emits: ['import-oauth-credentials', 'import-cookie-file'],
  template: `
    <div>
      <button
        data-testid="import-oauth-credentials"
        @click="$emit('import-oauth-credentials', '{}')"
      >import</button>
      <button
        data-testid="import-cookie-account"
        @click="$emit('import-cookie-file', 'cookie-blob', 'cookie_account')"
      >cookie</button>
    </div>
  `,
})

function mountModal() {
  return mount(CreateAccountModal, {
    props: { show: true, proxies: [], groups: [] },
    global: {
      stubs: {
        BaseDialog: BaseDialogStub,
        OAuthAuthorizationFlow: OAuthAuthorizationFlowStub,
        ConfirmDialog: true,
        Select: true,
        Icon: true,
        PlatformIcon: true,
        ProxySelector: true,
        ProxyAdBanner: true,
        GroupSelector: true,
        ModelWhitelistSelector: true,
        QuotaLimitCard: true,
      },
    },
  })
}

/**
 * Fills in step 1 for an Anthropic OAuth account with the account-control
 * switches turned on, then advances to the authorization step.
 */
async function openAnthropicAuthStepWithControls() {
  const wrapper = mountModal()
  await wrapper.get('form#create-account-form input[type="text"]').setValue('imported account')
  await wrapper.get('[data-testid="create-rpm-limit-toggle"]').trigger('click')
  await wrapper.get('[data-testid="create-tls-fingerprint-toggle"]').trigger('click')
  await wrapper.get('[data-testid="create-session-id-masking-toggle"]').trigger('click')
  await wrapper.get('form#create-account-form').trigger('submit.prevent')
  await flushPromises()
  return wrapper
}

describe('CreateAccountModal credential import applies account controls', () => {
  beforeEach(() => {
    createAccountMock.mockReset().mockResolvedValue({ id: 7, platform: 'anthropic', type: 'oauth' })
    importOAuthCredentialsMock.mockReset().mockResolvedValue({
      access_token: 'sk-ant-oat01-test',
      refresh_token: 'sk-ant-ort01-test',
      expires_at: 1787183506,
      email_address: 'operator@example.com',
    })
    validateClaudeCookieMock.mockReset().mockResolvedValue({
      credentials: { cookie_jar: 'sessionKey=x', org_uuid: 'org-1' },
      extra: { plan: 'max_20x' },
      info: { email_address: 'operator@example.com', org_name: 'Acme' },
    })
  })

  it('carries the RPM, TLS and session-masking switches into the imported OAuth account', async () => {
    const wrapper = await openAnthropicAuthStepWithControls()

    await wrapper.get('[data-testid="import-oauth-credentials"]').trigger('click')
    await flushPromises()

    expect(createAccountMock).toHaveBeenCalledTimes(1)
    const payload = createAccountMock.mock.calls[0]?.[0]
    expect(payload?.type).toBe('oauth')
    expect(payload?.platform).toBe('anthropic')
    expect(payload?.extra?.base_rpm).toBe(15)
    expect(payload?.extra?.rpm_strategy).toBe('tiered')
    expect(payload?.extra?.enable_tls_fingerprint).toBe(true)
    expect(payload?.extra?.session_id_masking_enabled).toBe(true)
  })

  it('keeps the operator-entered name and the scheduling fields on import', async () => {
    const wrapper = await openAnthropicAuthStepWithControls()

    await wrapper.get('[data-testid="import-oauth-credentials"]').trigger('click')
    await flushPromises()

    const payload = createAccountMock.mock.calls[0]?.[0]
    expect(payload?.name).toBe('imported account')
    expect(payload?.concurrency).toBe(10)
    expect(payload?.priority).toBe(1)
  })

  it('carries temp-unschedulable rules into the imported OAuth account', async () => {
    const wrapper = mountModal()
    await wrapper.get('form#create-account-form input[type="text"]').setValue('imported account')
    await wrapper.get('[data-testid="create-temp-unschedulable-toggle"]').trigger('click')
    const presetButton = wrapper
      .findAll('button')
      .find((candidate) => candidate.text().startsWith('+ '))
    expect(presetButton).toBeDefined()
    await presetButton?.trigger('click')
    await wrapper.get('form#create-account-form').trigger('submit.prevent')
    await flushPromises()

    await wrapper.get('[data-testid="import-oauth-credentials"]').trigger('click')
    await flushPromises()

    const payload = createAccountMock.mock.calls[0]?.[0]
    expect(payload?.credentials?.temp_unschedulable_enabled).toBe(true)
    expect(Array.isArray(payload?.credentials?.temp_unschedulable_rules)).toBe(true)
    expect((payload?.credentials?.temp_unschedulable_rules as unknown[]).length).toBeGreaterThan(0)
  })

  it('carries the same switches into a cookie account', async () => {
    const wrapper = await openAnthropicAuthStepWithControls()

    await wrapper.get('[data-testid="import-cookie-account"]').trigger('click')
    await flushPromises()

    expect(createAccountMock).toHaveBeenCalledTimes(1)
    const payload = createAccountMock.mock.calls[0]?.[0]
    expect(payload?.type).toBe('cookie')
    expect(payload?.extra?.base_rpm).toBe(15)
    expect(payload?.extra?.plan).toBe('max_20x')
    expect(payload?.credentials?.cookie_jar).toBe('sessionKey=x')
  })
})

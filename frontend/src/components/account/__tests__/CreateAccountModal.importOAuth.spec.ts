import { defineComponent } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'
import { beforeEach, describe, expect, it, vi } from 'vitest'

const {
  createAccountMock,
  importOAuthCredentialsMock,
  importRejectedMock,
  validateClaudeCookieMock,
} = vi.hoisted(() => ({
  createAccountMock: vi.fn(),
  importOAuthCredentialsMock: vi.fn(),
  importRejectedMock: vi.fn(),
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
      importOAuthCredentialsDetailed: async (payload: unknown) => ({
        accounts: await importOAuthCredentialsMock(payload),
        failed: importRejectedMock() ?? [],
      }),
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
    error: { type: String, default: '' },
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
      <span data-testid="flow-error">{{ error }}</span>
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
    importRejectedMock.mockReset().mockReturnValue([])
    importOAuthCredentialsMock.mockReset().mockResolvedValue([
      {
        access_token: 'sk-ant-oat01-test',
        refresh_token: 'sk-ant-ort01-test',
        expires_at: 1787183506,
        email_address: 'operator@example.com',
      },
    ])
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

  it('creates one account per imported credential, numbering the entered name', async () => {
    importOAuthCredentialsMock.mockResolvedValue([
      { access_token: 'a1', refresh_token: 'r1', email_address: 'one@example.com' },
      { access_token: 'a2', refresh_token: 'r2', email_address: 'two@example.com' },
      { access_token: 'a3', refresh_token: 'r3', email_address: 'three@example.com' },
    ])

    const wrapper = await openAnthropicAuthStepWithControls()
    await wrapper.get('[data-testid="import-oauth-credentials"]').trigger('click')
    await flushPromises()

    expect(createAccountMock).toHaveBeenCalledTimes(3)
    const names = createAccountMock.mock.calls.map((call) => call[0]?.name)
    expect(names).toEqual(['imported account #1', 'imported account #2', 'imported account #3'])

    const refreshTokens = createAccountMock.mock.calls.map(
      (call) => call[0]?.credentials?.refresh_token
    )
    expect(refreshTokens).toEqual(['r1', 'r2', 'r3'])

    // Every account in the batch gets the panel's switches, not just the first.
    for (const call of createAccountMock.mock.calls) {
      expect(call[0]?.extra?.base_rpm).toBe(15)
      expect(call[0]?.extra?.enable_tls_fingerprint).toBe(true)
    }
  })

  it('names each account after its own email when no name was entered', async () => {
    importOAuthCredentialsMock.mockResolvedValue([
      { access_token: 'a1', refresh_token: 'r1', email_address: 'one@example.com' },
      { access_token: 'a2', refresh_token: 'r2', email_address: 'two@example.com' },
    ])

    const wrapper = mountModal()
    // A name is required to leave step 1, so clear it once the auth step is open.
    await wrapper.get('form#create-account-form input[type="text"]').setValue('placeholder')
    await wrapper.get('form#create-account-form').trigger('submit.prevent')
    await flushPromises()
    ;(wrapper.vm as unknown as { form: { name: string } }).form.name = ''

    await wrapper.get('[data-testid="import-oauth-credentials"]').trigger('click')
    await flushPromises()

    const names = createAccountMock.mock.calls.map((call) => call[0]?.name)
    expect(names).toEqual(['one@example.com', 'two@example.com'])
  })

  it('keeps creating the rest of the batch when one account fails', async () => {
    importOAuthCredentialsMock.mockResolvedValue([
      { access_token: 'a1', refresh_token: 'r1', email_address: 'one@example.com' },
      { access_token: 'a2', refresh_token: 'r2', email_address: 'two@example.com' },
      { access_token: 'a3', refresh_token: 'r3', email_address: 'three@example.com' },
    ])
    createAccountMock
      .mockResolvedValueOnce({ id: 1 })
      .mockRejectedValueOnce(new Error('duplicate account'))
      .mockResolvedValueOnce({ id: 3 })

    const wrapper = await openAnthropicAuthStepWithControls()
    await wrapper.get('[data-testid="import-oauth-credentials"]').trigger('click')
    await flushPromises()

    expect(createAccountMock).toHaveBeenCalledTimes(3)
    // The failure is surfaced, so the modal stays open with the batch report.
    expect(wrapper.html()).toContain('admin.accounts.oauth.keyAuthFailed')
  })

  it('creates the importable accounts and reports the rejected credentials', async () => {
    importOAuthCredentialsMock.mockResolvedValue([
      { access_token: 'a2', refresh_token: 'r2', email_address: 'two@example.com' },
    ])
    importRejectedMock.mockReturnValue([{ index: 1, error: 'invalid_grant' }])

    const wrapper = await openAnthropicAuthStepWithControls()
    await wrapper.get('[data-testid="import-oauth-credentials"]').trigger('click')
    await flushPromises()

    expect(createAccountMock).toHaveBeenCalledTimes(1)
    expect(createAccountMock.mock.calls[0]?.[0]?.credentials?.refresh_token).toBe('r2')
    // The modal stays open so the operator sees which credential to re-export.
    expect(wrapper.html()).toContain('admin.accounts.oauth.keyAuthFailed')
  })

  it('reports rejected credentials when none could be imported', async () => {
    importOAuthCredentialsMock.mockResolvedValue([])
    importRejectedMock.mockReturnValue([{ index: 1, error: 'invalid_grant' }])

    const wrapper = await openAnthropicAuthStepWithControls()
    await wrapper.get('[data-testid="import-oauth-credentials"]').trigger('click')
    await flushPromises()

    expect(createAccountMock).not.toHaveBeenCalled()
    expect(wrapper.html()).toContain('admin.accounts.oauth.keyAuthFailed')
    expect(wrapper.html()).not.toContain('admin.accounts.oauth.importCredentialsEmpty')
  })

  it('reports an empty import instead of creating anything', async () => {
    importOAuthCredentialsMock.mockResolvedValue([])

    const wrapper = await openAnthropicAuthStepWithControls()
    await wrapper.get('[data-testid="import-oauth-credentials"]').trigger('click')
    await flushPromises()

    expect(createAccountMock).not.toHaveBeenCalled()
    expect(wrapper.html()).toContain('admin.accounts.oauth.importCredentialsEmpty')
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

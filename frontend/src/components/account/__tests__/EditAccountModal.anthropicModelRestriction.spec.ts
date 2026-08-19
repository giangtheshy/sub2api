import { beforeEach, describe, expect, it, vi } from 'vitest'
import { defineComponent } from 'vue'
import { flushPromises, mount } from '@vue/test-utils'

const { updateAccountMock, checkMixedChannelRiskMock } = vi.hoisted(() => ({
  updateAccountMock: vi.fn(),
  checkMixedChannelRiskMock: vi.fn()
}))

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({
    showError: vi.fn(),
    showSuccess: vi.fn(),
    showInfo: vi.fn()
  })
}))

vi.mock('@/stores/auth', () => ({
  useAuthStore: () => ({ isSimpleMode: true })
}))

vi.mock('@/api/admin', () => ({
  adminAPI: {
    accounts: {
      update: updateAccountMock,
      checkMixedChannelRisk: checkMixedChannelRiskMock
    },
    settings: {
      getWebSearchEmulationConfig: vi.fn().mockResolvedValue({ enabled: false, providers: [] }),
      getSettings: vi.fn().mockResolvedValue({})
    },
    tlsFingerprintProfiles: {
      list: vi.fn().mockResolvedValue([])
    }
  }
}))

vi.mock('@/api/admin/accounts', () => ({
  getAntigravityDefaultModelMapping: vi.fn()
}))

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({ t: (key: string) => key })
  }
})

import EditAccountModal from '../EditAccountModal.vue'

const BaseDialogStub = defineComponent({
  name: 'BaseDialog',
  props: { show: { type: Boolean, default: false } },
  template: '<div v-if="show"><slot /><slot name="footer" /></div>'
})

const ModelWhitelistSelectorStub = defineComponent({
  name: 'ModelWhitelistSelector',
  props: { modelValue: { type: Array, default: () => [] } },
  emits: ['update:modelValue'],
  template: `
    <div>
      <button
        type="button"
        data-testid="set-whitelist"
        @click="$emit('update:modelValue', ['claude-opus-4-6'])"
      >set</button>
      <button
        type="button"
        data-testid="clear-whitelist"
        @click="$emit('update:modelValue', [])"
      >clear</button>
      <span data-testid="model-whitelist-value">
        {{ Array.isArray(modelValue) ? modelValue.join(',') : '' }}
      </span>
    </div>
  `
})

const SelectStub = defineComponent({
  name: 'SelectStub',
  props: {
    modelValue: { type: [String, Number, Boolean, null], default: '' },
    options: { type: Array, default: () => [] }
  },
  emits: ['update:modelValue'],
  template: `
    <select v-bind="$attrs" :value="modelValue" @change="$emit('update:modelValue', $event.target.value)">
      <option v-for="option in options" :key="option.value" :value="option.value">{{ option.label }}</option>
    </select>
  `
})

function buildAnthropicSubscriptionAccount(
  type: 'oauth' | 'setup-token' | 'cookie' = 'oauth',
  modelMapping?: Record<string, string>
) {
  return {
    id: 11,
    name: 'cookies x20 1',
    notes: '',
    platform: 'anthropic',
    type,
    credentials: {
      // The API redacts tokens but keeps model_mapping, which is exactly why the
      // editor has to round-trip it instead of rebuilding from an empty state.
      ...(modelMapping ? { model_mapping: modelMapping } : {})
    },
    credentials_status: { has_access_token: true, has_refresh_token: true },
    extra: {},
    proxy_id: null,
    concurrency: 10,
    priority: 1,
    rate_multiplier: 1,
    status: 'active',
    group_ids: [],
    expires_at: null,
    auto_pause_on_expired: false
  } as any
}

function mountModal(account: any) {
  return mount(EditAccountModal, {
    props: { show: true, account, proxies: [], groups: [] },
    global: {
      stubs: {
        BaseDialog: BaseDialogStub,
        Select: SelectStub,
        Icon: true,
        ProxySelector: true,
        GroupSelector: true,
        ModelWhitelistSelector: ModelWhitelistSelectorStub
      }
    }
  })
}

async function submit(wrapper: ReturnType<typeof mountModal>) {
  await wrapper.get('form#edit-account-form').trigger('submit.prevent')
  await flushPromises()
}

describe('EditAccountModal Anthropic subscription model restriction', () => {
  beforeEach(() => {
    updateAccountMock.mockReset().mockResolvedValue({})
    checkMixedChannelRiskMock.mockReset().mockResolvedValue({ has_risk: false })
  })

  it('shows the restriction editor for oauth, setup-token and cookie accounts', () => {
    for (const type of ['oauth', 'setup-token', 'cookie'] as const) {
      const wrapper = mountModal(buildAnthropicSubscriptionAccount(type))
      expect(wrapper.find('[data-testid="model-whitelist-value"]').exists()).toBe(true)
    }
  })

  it('hydrates the whitelist from an existing model_mapping', () => {
    const wrapper = mountModal(
      buildAnthropicSubscriptionAccount('oauth', {
        'claude-opus-4-6': 'claude-opus-4-6',
        'claude-sonnet-5': 'claude-sonnet-5'
      })
    )

    expect(wrapper.get('[data-testid="model-whitelist-value"]').text()).toBe(
      'claude-opus-4-6,claude-sonnet-5'
    )
  })

  it('preserves a bulk-edit whitelist when the dialog is submitted untouched', async () => {
    const wrapper = mountModal(
      buildAnthropicSubscriptionAccount('oauth', { 'claude-opus-4-6': 'claude-opus-4-6' })
    )

    await submit(wrapper)

    const payload = updateAccountMock.mock.calls[0]?.[1]
    expect(payload?.credentials?.model_mapping).toEqual({ 'claude-opus-4-6': 'claude-opus-4-6' })
  })

  it('persists a newly selected whitelist as model_mapping', async () => {
    const wrapper = mountModal(buildAnthropicSubscriptionAccount('oauth'))

    await wrapper.get('[data-testid="set-whitelist"]').trigger('click')
    await submit(wrapper)

    const payload = updateAccountMock.mock.calls[0]?.[1]
    expect(payload?.credentials?.model_mapping).toEqual({ 'claude-opus-4-6': 'claude-opus-4-6' })
  })

  it('drops model_mapping when the whitelist is cleared, restoring all models', async () => {
    const wrapper = mountModal(
      buildAnthropicSubscriptionAccount('oauth', { 'claude-opus-4-6': 'claude-opus-4-6' })
    )

    await wrapper.get('[data-testid="clear-whitelist"]').trigger('click')
    await submit(wrapper)

    const payload = updateAccountMock.mock.calls[0]?.[1]
    expect(payload?.credentials).toBeDefined()
    expect(payload?.credentials?.model_mapping).toBeUndefined()
  })
})

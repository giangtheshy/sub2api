import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import AccountActionMenu from '../AccountActionMenu.vue'
import type { Account } from '@/types'

vi.mock('vue-i18n', async () => {
  const actual = await vi.importActual<typeof import('vue-i18n')>('vue-i18n')
  return {
    ...actual,
    useI18n: () => ({
      t: (key: string) => key,
    }),
  }
})

function makeAccount(overrides: Partial<Account>): Account {
  return {
    id: 1,
    name: 'test-account',
    platform: 'anthropic',
    type: 'oauth',
    proxy_id: null,
    concurrency: 3,
    priority: 50,
    status: 'active',
    error_message: null,
    last_used_at: null,
    expires_at: null,
    auto_pause_on_expired: false,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    schedulable: true,
    rate_limited_at: null,
    rate_limit_reset_at: null,
    overload_until: null,
    temp_unschedulable_until: null,
    temp_unschedulable_reason: null,
    session_window_start: null,
    session_window_end: null,
    session_window_status: null,
    ...overrides,
  }
}

const position = { top: 100, left: 100 }
const MENU_KEY = 'admin.accounts.claudeCli.menuLabel'
const getBodyText = () => document.body.textContent ?? ''

// The export produces a file containing the account's Anthropic OAuth token
// pair. Offering it where no such pair exists hands the operator a file that
// cannot work, and — for a cookie account — puts a live claude.ai session on
// screen for nothing. The menu condition mirrors the backend predicate
// (service.Account.IsAnthropicOAuthOrSetupToken); these cases keep the two
// from drifting apart.
describe('AccountActionMenu — Claude CLI export visibility', () => {
  it('offers the export for an Anthropic OAuth account', () => {
    const wrapper = mount(AccountActionMenu, {
      props: { show: true, account: makeAccount({}), position },
      attachTo: document.body,
    })
    expect(getBodyText()).toContain(MENU_KEY)
    wrapper.unmount()
  })

  it('offers the export for an Anthropic setup-token account', () => {
    const wrapper = mount(AccountActionMenu, {
      props: { show: true, account: makeAccount({ type: 'setup-token' }), position },
      attachTo: document.body,
    })
    expect(getBodyText()).toContain(MENU_KEY)
    wrapper.unmount()
  })

  it.each([
    ['cookie account', { type: 'cookie' }],
    ['Anthropic API key account', { type: 'apikey' }],
    ['OpenAI OAuth account', { platform: 'openai' }],
    ['Gemini OAuth account', { platform: 'gemini' }],
    ['shadow account', { parent_account_id: 7 }],
  ])('hides the export for a %s', (_label, overrides) => {
    const wrapper = mount(AccountActionMenu, {
      props: { show: true, account: makeAccount(overrides as Partial<Account>), position },
      attachTo: document.body,
    })
    expect(getBodyText()).not.toContain(MENU_KEY)
    wrapper.unmount()
  })

  it('emits export-claude-cli with the account when clicked', async () => {
    const account = makeAccount({})
    const wrapper = mount(AccountActionMenu, {
      props: { show: true, account, position },
      attachTo: document.body,
    })

    const button = Array.from(document.body.querySelectorAll('button')).find(b =>
      b.textContent?.includes(MENU_KEY)
    )
    expect(button).toBeTruthy()
    button!.click()
    await wrapper.vm.$nextTick()

    expect(wrapper.emitted('export-claude-cli')?.[0]).toEqual([account])
    wrapper.unmount()
  })
})

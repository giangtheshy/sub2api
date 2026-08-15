import { describe, expect, it, vi } from 'vitest'

vi.mock('@/stores/app', () => ({
  useAppStore: () => ({ showError: vi.fn() })
}))

vi.mock('@/api/admin', () => ({
  adminAPI: { accounts: { exchangeCode: vi.fn(), generateAuthUrl: vi.fn() } }
}))

import { resolveAuthErrorMessage, useAccountOAuth } from '../useAccountOAuth'

const translate = (key: string) => {
  const messages: Record<string, string> = {
    'admin.accounts.oauth.cookieSessionStale': 'Session too old — sign in again',
    'admin.accounts.oauth.cookieInvalid': 'Cookie rejected',
    'admin.accounts.oauth.cookieOrgUnavailable': 'No chat organization',
    'admin.accounts.oauth.authFailed': 'Authorization failed'
  }
  return messages[key] ?? key
}

const netscapeExport = [
  '# Netscape HTTP Cookie File',
  '#HttpOnly_.claude.ai\tTRUE\t/\tTRUE\t1786790015\t__cf_bm\tcfvalue',
  '.claude.ai\tTRUE\t/\tTRUE\t1786875405\tsessionKey\tsk-ant-sid02-primary'
].join('\n')

describe('resolveAuthErrorMessage', () => {
  it('translates the stale-session reason into an actionable message', () => {
    // The backend flags this case with a reason code; the raw message is English.
    const error = {
      status: 400,
      reason: 'CLAUDE_SESSION_STALE',
      message: 'claude.ai session is too old to grant OAuth access.'
    }

    expect(resolveAuthErrorMessage(error, translate, 'admin.accounts.oauth.authFailed')).toBe(
      'Session too old — sign in again'
    )
  })

  it.each([
    ['CLAUDE_COOKIE_INVALID', 'Cookie rejected'],
    ['CLAUDE_ORG_UNAVAILABLE', 'No chat organization']
  ])('translates %s', (reason, expected) => {
    expect(
      resolveAuthErrorMessage({ reason }, translate, 'admin.accounts.oauth.authFailed')
    ).toBe(expected)
  })

  it('falls back to the backend message for unknown reasons', () => {
    const error = { reason: 'SOMETHING_ELSE', message: 'upstream exploded' }

    expect(resolveAuthErrorMessage(error, translate, 'admin.accounts.oauth.authFailed')).toBe(
      'upstream exploded'
    )
  })

  it('uses the backend message when there is no reason code', () => {
    // Regression guard: the axios interceptor rejects with a flat object, so
    // reading error.response.data.detail always yielded undefined and every
    // failure collapsed into the generic fallback.
    expect(
      resolveAuthErrorMessage({ message: 'status 403' }, translate, 'admin.accounts.oauth.authFailed')
    ).toBe('status 403')
  })

  it('falls back to the generic message for an empty error', () => {
    expect(resolveAuthErrorMessage({}, translate, 'admin.accounts.oauth.authFailed')).toBe(
      'Authorization failed'
    )
    expect(resolveAuthErrorMessage(null, translate, 'admin.accounts.oauth.authFailed')).toBe(
      'Authorization failed'
    )
  })
})

describe('useAccountOAuth().isCookieExport', () => {
  const { isCookieExport, parseSessionKeys } = useAccountOAuth()

  it('detects a Netscape export', () => {
    expect(isCookieExport(netscapeExport)).toBe(true)
  })

  it('detects JSON exports', () => {
    expect(isCookieExport('[{"name":"sessionKey","value":"sk-ant-sid02-x"}]')).toBe(true)
    expect(isCookieExport('{"sessionKey":"sk-ant-sid02-x"}')).toBe(true)
  })

  it('does not treat a batch of sessionKeys as an export', () => {
    const batch = 'sk-ant-sid02-a\nsk-ant-sid02-b'
    expect(isCookieExport(batch)).toBe(false)
    expect(parseSessionKeys(batch)).toEqual(['sk-ant-sid02-a', 'sk-ant-sid02-b'])
  })

  it('does not treat a single sessionKey as an export', () => {
    expect(isCookieExport('  sk-ant-sid02-single  ')).toBe(false)
  })

  it('does not treat a Cookie header string as a multi-account batch', () => {
    // A header is one line, so line splitting already yields a single entry.
    const header = 'anthropic-device-id=dev-1; sessionKey=sk-ant-sid02-x'
    expect(parseSessionKeys(header)).toHaveLength(1)
  })
})

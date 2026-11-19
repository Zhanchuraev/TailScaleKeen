// Optional: node --test tests/native-connection-browser.cjs with Playwright installed.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright');

let browser;
before(async () => { browser = await chromium.launch({ channel: process.env.TSK_CHROMIUM_CHANNEL }); });
after(async () => { if (browser) await browser.close(); });
const origin = 'http://keenetic.test';
const web = path.resolve(__dirname, '../web');

async function fixture(t, authenticated = true) {
    const page = await browser.newPage();
    t.after(() => page.context().close());
    page.setDefaultTimeout(8000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    t.after(() => assert.deepEqual(errors, []));
    const state = { available: false, exists: false, priorityAvailable: true, reads: 0, plans: [], applies: 0, finish: false };
    await page.route('**/*', async route => {
        const url = new URL(route.request().url());
        if (url.origin !== origin) return route.abort();
        const p = url.pathname;
        if (p === '/') return route.fulfill({ path: path.join(web, 'index.html') });
        if (p.startsWith('/static/')) return route.fulfill({ path: path.join(web, p.slice(8)) });
        const json = (obj, status = 200) => route.fulfill({ json: obj, status });
        if (p === '/api/session') return json({ authenticated, configured: true, csrf: 'fixture', version: '1.2.0' });
        if (!authenticated) return json({ error: 'Требуется вход' }, 401);
        if (p === '/api/dashboard') return json({
            panel_version: '1.2.0', config: { tun: 'opkgtun2' }, system: {},
            tailscale: { backend_state: 'Running', online: true, prefs: {}, self: {}, peers: [], health: [] },
        });
        if (p === '/api/native') {
            assert.equal(route.request().method(), 'GET');
            state.reads++;
            if (state.hold) await state.hold;
            if (!state.available) return json({ available: false, error: 'Нет ответа от KeeneticOS' });
            return json({ available: true, exists: state.exists, name: 'OpkgTun2', tun: 'opkgtun2', mtu: '1280',
                          description: 'Tailscale', connected: true, priority_available: state.priorityAvailable,
                          global: state.exists && state.plans.at(-1)?.params.global, policies: [] });
        }
        if (p === '/api/actions/plan') {
            state.plans.push(route.request().postDataJSON());
            return json({ id: 'preview', commands: ['interface OpkgTun2'],
                          changes: [{ name: 'Подключение', before: 'Отсутствует', after: 'OpkgTun2' }],
                          message: 'Зарегистрировать интерфейс Tailscale' });
        }
        if (p === '/api/actions/apply') {
            assert.deepEqual(route.request().postDataJSON(), { plan_id: 'preview' });
            state.applies++; return json({ id: 'native-job' });
        }
        if (p === '/api/jobs/native-job') {
            if (state.finish) state.exists = true;
            return json({ label: 'Подключение Keenetic', state: state.finish ? 'done' : 'running', log: [] });
        }
        return json({ error: 'Unknown fixture endpoint ' + p }, 404);
    });
    await page.goto(origin + '/#native');
    return { page, state };
}

test('check distinguishes unavailable, missing and registered; create requires explicit confirmation', async t => {
    const { page, state } = await fixture(t);
    const check = page.getByRole('button', { name: 'Проверить подключение', exact: true });
    const create = page.getByRole('button', { name: 'Создать подключение Tailscale' });
    await page.getByRole('alert').filter({ hasText: 'Нет ответа от KeeneticOS' }).waitFor();
    assert.equal(await create.count(), 0);

    state.available = true;
    let releaseRead;
    state.hold = new Promise(resolve => { releaseRead = resolve; });
    await check.click();
    assert.equal(await page.locator('#native-check').isDisabled(), true);
    releaseRead(); state.hold = null;
    await create.waitFor();
    assert.equal(state.reads, 2);
    assert.deepEqual(state.plans, []);
    await page.locator('#native-form summary').click();
    await page.locator('#native-form [name=description]').fill('Рабочая сеть');
    await check.click();
    await page.locator('#native-status[aria-busy=false]').waitFor();
    assert.equal(await page.locator('#native-form [name=description]').inputValue(), 'Рабочая сеть');
    await create.click();
    await page.locator('#confirm[open]').waitFor();
    assert.deepEqual(state.plans, [{ action: 'native_create', params: {
        description: 'Рабочая сеть', mtu: 1280, global: true, save: true,
    } }]);
    assert.equal(state.applies, 0);
    await page.locator('#confirm-apply').click();
    await page.locator('#job-dialog[open]').waitFor();
    await page.locator('#job-close').click();
    assert.equal(await create.isDisabled(), true);
    state.finish = true;
    await page.getByText('Зарегистрировано', { exact: true }).waitFor();
    assert.equal(await page.locator('#native-status dt').filter({ hasText: 'В «Приоритетах подключений»' })
                           .locator('+ dd').innerText(), 'Да');
    assert.equal(await create.count(), 0);
    await check.click();
    await page.locator('#native-status[aria-busy=false]').waitFor();
    assert.equal(state.applies, 1);
    assert.equal(state.plans.length, 1);
});

test('manual opt-out survives a check; priority is disabled without a confirmed higher-priority uplink', async t => {
    const { page, state } = await fixture(t);
    await page.getByRole('alert').filter({ hasText: 'Нет ответа от KeeneticOS' }).waitFor();
    state.available = true;
    const check = page.getByRole('button', { name: 'Проверить подключение', exact: true });
    await check.click();
    await page.locator('#native-form summary').click();
    const priority = page.getByRole('switch', { name: /Показывать в «Приоритетах подключений»/ });
    assert.equal(await priority.isChecked(), true);
    await priority.uncheck();
    await check.click();
    await page.locator('#native-status[aria-busy=false]').waitFor();
    assert.equal(await priority.isChecked(), false);
    state.priorityAvailable = false;
    await check.click();
    await page.locator('#native-status[aria-busy=false]').waitFor();
    assert.equal(await priority.isDisabled(), true);
    assert.equal(await priority.isChecked(), false);
    await page.getByRole('button', { name: 'Создать подключение Tailscale' }).click();
    await page.locator('#confirm[open]').waitFor();
    assert.equal(state.plans[0].params.global, false);
});

test('login is required before querying the native interface or showing controls', async t => {
    const { page, state } = await fixture(t, false);
    await page.locator('#login-screen').waitFor();
    assert.equal(await page.locator('#native-check').count(), 0);
    assert.equal(state.reads, 0);
});

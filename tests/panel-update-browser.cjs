// Optional browser test: node --test tests/panel-update-browser.cjs with Playwright installed.
// Set TSK_CHROMIUM_CHANNEL=chrome to use an installed Google Chrome.
const { before, after, test } = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { setTimeout: delay } = require('node:timers/promises');
const { chromium } = require('playwright');

const web = path.resolve(__dirname, '../web');
const origin = 'http://panel.test';
const transaction = '0123456789abcdef01234567';
const older = 'aaaaaaaaaaaaaaaaaaaaaaaa';
const previous = '1.2.0', latest = '1.3.0';
let browser;
before(async () => { browser = await chromium.launch({ channel: process.env.TSK_CHROMIUM_CHANNEL }); });
after(async () => { if (browser) await browser.close(); });

async function until(check, message) {
    const deadline = Date.now() + 15000;
    while (!await check()) {
        if (Date.now() >= deadline) assert.fail(message);
        await delay(80);
    }
}

async function fixture(t, { completedWithoutMarker = false, holdApply = false, section = 'system' } = {}) {
    const page = await browser.newPage();
    t.after(() => page.context().close());
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    t.after(() => assert.deepEqual(errors, []));
    const state = { authenticated: !completedWithoutMarker, version: completedWithoutMarker ? latest : previous,
                    result: {}, fault: '', apply: 0, polls: 0, loads: 0 };
    let releaseApply;
    const applyGate = new Promise(resolve => { releaseApply = resolve; });
    const now = () => Math.floor(Date.now() / 1000);
    function report(status, message, id = transaction) {
        state.result = { id, state: status, version: latest, from_version: previous,
                         started_at: now() - 10, message };
        if (['done', 'error', 'rolled_back'].includes(status)) state.result.finished_at = now();
    }
    if (completedWithoutMarker) report('done', 'Успешный запуск новой версии');
    // Serve the project's actual HTML, CSS, and JavaScript. Only the router is simulated.
    await page.route('**/*', async route => {
        const url = new URL(route.request().url());
        if (url.origin !== origin) return route.abort();
        const p = url.pathname;
        if (p === '/') {
            state.loads++;
            return route.fulfill({ path: path.join(web, 'index.html') });
        }
        if (p.startsWith('/static/')) return route.fulfill({ path: path.join(web, p.slice(8)) });
        const json = (obj, status = 200) => route.fulfill({ status, json: obj });
        if (p === '/api/session') {
            if (url.searchParams.get('update_id') === transaction) {
                state.polls++;
                if (state.fault === 'disconnect') return route.abort('connectionreset');
                if (state.fault === '401') return json({ error: 'Требуется вход' }, 401);
            }
            return json({ authenticated: state.authenticated, configured: true, version: state.version,
                          user: state.authenticated ? 'test' : '', csrf: 'fixture', panel_update: state.result });
        }
        if (!state.authenticated) return json({ error: 'Требуется вход' }, 401);
        if (p === '/api/dashboard') return json({
            panel_version: state.version, config: { auth_source: 'local', port: 8092 },
            system: { architecture: 'fixture' },
            tailscale: { backend_state: 'Running', online: true, version: '1.0', prefs: {}, self: {}, peers: [], health: [] },
        });
        if (p === '/api/panel-settings') return json({ username: 'test', port: 8092 });
        if (p === '/api/panel-update-status') return json(state.journal || state.result);
        if (p === '/api/panel-updates') return json({ current: previous, latest, available: true });
        if (p === '/api/actions/plan') {
            assert.equal(route.request().postDataJSON().action, 'update_panel');
            return json({ id: 'preview', action: 'update_panel', transaction, version: latest, commands: [],
                          message: 'Проверка обновления', changes: [{ name: 'Версия', before: previous, after: latest }] });
        }
        if (p === '/api/actions/apply') {
            assert.equal(route.request().postDataJSON().plan_id, 'preview');
            state.apply++;
            if (holdApply) {
                await applyGate;
                return route.abort('connectionreset');
            }
            return json({ id: transaction, state: 'running', label: 'Обновление WebUI' });
        }
        if (p === '/api/jobs/' + transaction) return json(state.job || { id: transaction, state: 'running', log: [] });
        return json({ error: 'Unknown fixture endpoint ' + p }, 404);
    });
    await page.goto(origin + '/#' + section);
    const dialog = page.locator('#panel-update-dialog');
    if (!completedWithoutMarker) {
        await page.getByRole('button', { name: 'Обновить WebUI TailScaleKeen' }).click();
        await page.locator('#confirm-apply').click();
        await dialog.waitFor({ state: 'visible' });
        await until(() => state.apply === 1, 'Apply must start once');
    }
    async function nextPoll() {
        const n = state.polls;
        await until(() => state.polls > n, 'The browser must query the specific update transaction');
        await delay(120);
    }
    return { page, state, dialog, report, nextPoll, releaseApply };
}

test('browser follows the same update across download, loss of session, restart and reload', async t => {
    const { page, state, dialog, report, nextPoll, releaseApply } = await fixture(t, { holdApply: true });
    const marker = () => page.evaluate(() => localStorage.getItem('tailscalekeen-update'));
    const dismiss = dialog.locator('#panel-update-dismiss');
    // No finished job result is ever returned to the browser.
    report('done', 'Чужая завершённая операция', older);
    await nextPoll();
    assert.ok(await marker(), 'Old result for the same target version must not complete this request');
    assert.ok(!(await dialog.innerText()).includes('Чужая завершённая операция'));
    report('preparing', 'Загрузка и проверка архива');
    await nextPoll();
    assert.ok((await dialog.innerText()).includes('Загрузка и проверка архива'));
    releaseApply();
    await page.reload();
    await dialog.waitFor({ state: 'visible' });
    state.fault = 'disconnect';
    await nextPoll();
    state.authenticated = false;
    state.fault = '401';
    await nextPoll();
    state.fault = '';
    report('checking', 'Проверка связи с панелью');
    await nextPoll();
    assert.ok(await dialog.isVisible());
    const loads = state.loads;
    report('done', 'Установка завершена, запущена старая версия');
    await nextPoll();
    assert.equal(state.loads, loads, 'An outdated running binary must not be reported as an updated frontend');
    assert.equal(await dialog.locator('#panel-update-heading').innerText(), 'Обновление TailScaleKeen');
    state.version = latest;
    report('done', 'Обновление завершено');
    await until(() => state.loads > loads, 'A verified new version should load its new frontend');
    await dismiss.waitFor({ state: 'visible' });
    assert.equal(await dialog.locator('#panel-update-heading').innerText(), 'Панель обновлена');
    assert.match(await dialog.innerText(), /1\.3\.0/);
    await page.reload();
    await dismiss.waitFor({ state: 'visible' });
    assert.match(await dialog.innerText(), /1\.3\.0/);
    await dismiss.click();
    await dialog.waitFor({ state: 'hidden' });
    state.authenticated = true;
    await page.reload();
    await page.locator('#check-panel-update').waitFor();
    assert.equal(await dialog.isVisible(), false, 'Acknowledged result must stay closed');
    assert.equal(state.apply, 1);
});

test('recent result remains readable at sign-in after the old UI removed its marker', async t => {
    const { page, state, dialog } = await fixture(t, { completedWithoutMarker: true });
    await dialog.waitFor({ state: 'visible' });
    assert.equal(await dialog.locator('#panel-update-heading').innerText(), 'Панель обновлена');
    assert.match(await dialog.innerText(), /1\.3\.0/);
    await dialog.getByRole('button', { name: 'Закрыть' }).click();
    await page.reload();
    await page.locator('#login-form').waitFor();
    assert.equal(await dialog.isVisible(), false);
    assert.equal(state.apply, 0);
});

test('ordinary sign-in outside the update page has no unsolicited result popup', async t => {
    const { page, state, dialog } = await fixture(t, { completedWithoutMarker: true, section: 'overview' });
    await page.locator('#login-form').waitFor();
    assert.equal(await dialog.isVisible(), false);
    assert.equal(state.apply, 0);
});

for (const outcome of ['error', 'rolled_back']) {
    test('browser keeps the ' + outcome + ' result until dismissed', async t => {
        const { page, state, dialog, report } = await fixture(t);
        const heading = outcome === 'error' ? 'Обновление не завершено' : 'Восстановлена прежняя версия';
        const detail = outcome === 'error' ? 'Тестовая причина: архив повреждён' : 'Тестовая причина: проверка запуска завершилась ошибкой';
        report(outcome, 'Публичный результат');
        state.journal = { ...state.result, message: detail };
        if (outcome === 'error') state.job = { id: transaction, panel_update_version: latest, error: detail };
        await until(async () => await dialog.locator('#panel-update-heading').innerText() === heading,
                    'Terminal outcome should be visible');
        const dismiss = dialog.locator('#panel-update-dismiss');
        await dismiss.waitFor({ state: 'visible' });
        await page.reload();
        await dismiss.waitFor({ state: 'visible' });
        assert.equal(await dialog.locator('#panel-update-heading').innerText(), heading);
        assert.equal((await dialog.innerText()).includes(detail), false);
        await dialog.locator('#panel-update-details').click();
        await until(async () => await dialog.locator('#panel-update-detail').innerText() === detail,
                    'Authenticated details should identify the exact failed job or rollback');
        assert.equal(await page.evaluate(s => JSON.stringify(localStorage).includes(s), detail), false);
        await dismiss.click();
        await page.reload();
        await page.locator('#check-panel-update').waitFor();
        assert.equal(await dialog.isVisible(), false);
        assert.equal(state.apply, 1);
    });
}

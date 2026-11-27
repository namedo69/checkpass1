// Offline UI timer checks: node --test test_uplv_job_timer.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

for (const name of ['uplv_admin.html', 'uplv_user.html']) {
  const html = fs.readFileSync(path.join(process.env.UPLV_HTML_DIR || __dirname, name), 'utf8');
  const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
  const helpers = script.slice(script.indexOf('function elapsedSince('),
    script.indexOf('setInterval(()=>{if(!document.hidden)updateJobTimers();},1000);'));
  const context = vm.createContext({
    esc: value => String(value).replace(/[&<>"']/g, ''),
    document: { querySelectorAll: () => [] },
  });
  vm.runInContext(helpers, context);

  test(`${name}: complete inline JavaScript parses`, () => {
    new vm.Script(script);
    assert.ok(script.includes('${renderJobTime(j)}'));
    assert.ok(script.includes('setInterval(()=>{if(!document.hidden)updateJobTimers();},1000)'));
    assert.ok(script.includes("document.addEventListener('visibilitychange'"));
  });

  test(`${name}: elapsed time survives refresh and handles day boundaries`, () => {
    const start = 1795770769;
    const format = seconds => context.elapsedSince(start, start * 1000 + seconds * 1000);
    assert.equal(format(0), '00:00:00');
    assert.equal(format(59), '00:00:59');
    assert.equal(format(60), '00:01:00');
    assert.equal(format(3661), '01:01:01');
    assert.equal(format(86400), '1 ngày 00:00:00');
    assert.equal(format(176461), '2 ngày 01:01:01');
    assert.equal(format(-10), '00:00:00');
    assert.equal(format(3661), '01:01:01');
    for (const value of [undefined, null, '', 0, -1, 'invalid', Infinity]) {
      assert.equal(context.elapsedSince(value), '—');
    }
  });

  test(`${name}: Vietnam creation date and explicit age label`, () => {
    const rendered = context.renderJobTime({ created_at: 1795770769, status: 'open' });
    assert.ok(rendered.includes('16:12:49'));
    assert.ok(rendered.includes('27/11/2026'));
    assert.ok(rendered.includes('Từ lúc tạo:'));
    assert.ok(rendered.includes('data-job-created="1795770769"'));
    assert.equal(context.renderJobTime({}), 'Thời gian tạo: chưa rõ');
    assert.equal(context.renderJobTime({ created_at: '"><img src=x>' }), 'Thời gian tạo: chưa rõ');
  });

  test(`${name}: ended jobs show creation time without a live counter`, () => {
    for (const status of ['done', 'stopped', 'failed', undefined]) {
      const rendered = context.renderJobTime({ created_at: 1795770769, status });
      assert.ok(rendered.includes('16:12:49'));
      assert.ok(!rendered.includes('data-job-created'));
      assert.ok(!rendered.includes('Từ lúc tạo:'));
    }
    assert.ok(context.renderJobTime({ created_at: 1795770769, status: 'open' }).includes('data-job-created'));
    assert.ok(!context.renderJobTime({ created_at: 1795770769, status: 'done' }).includes('data-job-created'));
  });

  test(`${name}: ticks update only timer text, without API requests`, () => {
    const element = { dataset: { jobCreated: 1795770769 }, textContent: '' };
    context.document.querySelectorAll = selector => {
      assert.equal(selector, '[data-job-created]');
      return [element];
    };
    vm.runInContext('Date.now = () => 1795770769000 + 65000', context);
    context.updateJobTimers();
    assert.equal(element.textContent, '00:01:05');
    vm.runInContext('Date.now = () => 1795770769000 + 66000', context);
    context.updateJobTimers();
    assert.equal(element.textContent, '00:01:06');
  });
}

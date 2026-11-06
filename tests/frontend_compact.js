const {JSDOM, VirtualConsole} = require('jsdom');
const fs = require('fs'), path = require('path'), assert = require('assert/strict');
const root = process.env.INFO_TEST_STATIC || path.join(__dirname, '..', 'app', 'static');
const read = name => fs.readFileSync(path.join(root, name), 'utf8');
const kpis = Array.from({length: 14}, (_, i) => ({id: 'k' + i, label: 'Показатель ' + i, value: i === 0 ? null : i, status: i === 0 ? 'unknown' : 'historical', period: '2026-10-29', source: 'PRIVATE_SOURCE_TRACE', error: 'PRIVATE_DEBUG_TRACE'}));
const technicalIssue = 'Расходы/комиссии/возвраты не reconciled; прибыль неизвестна, не0';
const project = {id: 'demo', name: 'Проект', state: 'warn', stage: 'Восстановлено из копии', issues: [{severity:'warn', text:'PRIVATE_ISSUE_TRACE'}, {severity:'warn', text:technicalIssue}], analytics: {kpis, error:'PRIVATE_ANALYTICS_TRACE', tables:[], charts:[]}};
project.analytics.matrices = [{id:'exits',title:'Связность',columns:['up0','up1','up2'],rows:[
  {label:'ru2',cells:[{state:'ok',title:'up0 · Финляндия · 52 мс'},{state:'off',title:'up1 · выключен'},{state:'bad',title:'up2 · Казахстан'}]},
  {label:'ru3',cells:[{state:'off',title:'up0 · Финляндия · выключен'},{state:'off',title:'up1 · выключен'},{state:'bad',title:'up2 · Казахстан'}]}
]}];
const originalMatrix = JSON.stringify(project.analytics.matrices);
const bonds = {id:'bonds', name:'BondAI', stage:'Восстановлено из копии', issues:[], analytics:{kpis:[
  {id:'owner', label:'Оценка одного портфеля', value:210000},
  {id:'cost', label:'Стоимость покупки', value:200000},
  {id:'users', label:'Пользователи сервиса', value:684},
  {id:'portfolios', label:'Портфели сервиса', value:1842}
]}};
const overview = {ready:true, refresh_sec:60, generated_at:'2026-11-04T00:00:00Z', projects:[project,bonds], tls:[], server_groups:[]};
let html = read('index.html');
for (const file of ['app.js', 'views.js']) html = html.replace(new RegExp('<script src="/static/' + file.replace('.', '\\.') + '[^"]*"></script>'), '<script>' + read(file) + '</script>');
const errors = [], vc = new VirtualConsole();
vc.on('jsdomError', e => errors.push(e.message));
const dom = new JSDOM(html, {url:'https://info.test/#overview', runScripts:'dangerously', pretendToBeVisual:true, virtualConsole:vc,
  beforeParse(w) {
    w.scrollTo = () => {};
    w.fetch = async url => ({ok:true, status:200, headers:new Map(), json:async () => {
      if (String(url).includes('/api/auth/status')) return {has_password:true, logged_in:true};
      if (String(url) === '/api/projects/demo') return project;
      if (String(url) === '/api/projects/bonds') return bonds;
      if (String(url) === '/api/projects') return overview;
      return {servers:[]};
    }});
  }
});
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
(async () => {
  await pause(200);
  const d = dom.window.document;
  assert.equal(d.querySelectorAll('#overviewView .project-row').length, 2);
  assert.equal(d.querySelectorAll('#overviewView .figure-value').length, 4);
  const bondsRow = d.querySelector('#overviewView a.project-row[href="#projects/bonds"]');
  assert.deepEqual([...bondsRow.querySelectorAll('.figure-value')].map(n=>n.textContent.replace(/\s/g,'')), ['684','1842']);
  assert([...d.querySelectorAll('#overviewView .ins-top b')].some(n=>n.textContent==='Прибыль пока не подтверждена'));
  assert([...d.querySelectorAll('#overviewView .issue-detail')].some(n=>!n.open && n.textContent.includes(technicalIssue)));
  assert(!d.querySelector('#overviewView').textContent.includes('PRIVATE_SOURCE_TRACE'));
  assert(!d.querySelector('#overviewView .technical-section').open);
  dom.window.location.hash = '#projects/demo';
  await pause(100);
  assert.equal(d.querySelectorAll('#projectsView > .stats .stat').length, 6);
  assert.equal(d.querySelectorAll('#projectsView .stat').length, 14);
  assert(![...d.querySelectorAll('#projectsView .matrix .mh')].some(n=>n.title==='up1'));
  assert.equal(d.querySelectorAll('#projectsView .matrix .mc').length, 4);
  assert.equal(d.querySelectorAll('#projectsView .matrix .mc.bad').length, 2);
  assert.equal(d.querySelectorAll('#projectsView .matrix .mc.off').length, 1);
  assert.equal(JSON.stringify(project.analytics.matrices), originalMatrix);
  for (const text of ['PRIVATE_SOURCE_TRACE', 'PRIVATE_DEBUG_TRACE']) {
    const node = [...d.querySelectorAll('#projectsView p')].find(n => n.textContent.includes(text));
    assert(node && node.closest('details') && !node.closest('details').open, text + ' must be in a closed disclosure');
  }
  const diagnostics = d.querySelector('.project-diagnostics');
  assert(!diagnostics.open);
  assert(diagnostics.textContent.includes('PRIVATE_ISSUE_TRACE'));
  assert(diagnostics.textContent.includes('PRIVATE_ANALYTICS_TRACE'));
  const unknown = [...d.querySelectorAll('#projectsView .stat')].find(n => n.textContent.includes('Показатель 0'));
  assert(unknown.textContent.includes('нет данных'));
  const disclosure = d.querySelector('#projectsView .metric-info');
  disclosure.open = true;
  assert(disclosure.textContent.includes('PRIVATE_SOURCE_TRACE'));
  await pause(20);
  dom.window.dispatchEvent(new dom.window.Event('resize'));
  await pause(350);
  assert(d.querySelector('#projectsView .metric-info').open, 'An open source disclosure must survive refresh');
  assert.deepEqual(errors, []);
  console.log('ok compact overview, 6 primary/14 retained metrics, closed diagnostics and accessible provenance');
  dom.window.close();
})().catch(e => { console.error(e.message); dom.window.close(); process.exit(1); });

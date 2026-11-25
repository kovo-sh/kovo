type Stage = 'discover' | 'review' | 'analyze' | 'verify' | 'done';
const hosts = [
  { name: 'northstar.example', description: 'Primary website', thirdParty: false },
  { name: 'portal.northstar.example', description: 'Customer portal', thirdParty: false },
  { name: 'docs.northstar.example', description: 'Documentation', thirdParty: false },
  { name: 'help.vendor.example', description: 'Third-party help center', thirdParty: true },
];
const phases = [
  { title: 'Discovery', workers: [
    'Seed inventory', 'Domain ownership records', 'Portal inventory', 'Documentation inventory',
    'Service catalog import', 'Duplicate asset review', 'Third-party classification', 'Scope review preparation',
  ] },
  { title: 'Analysis', workers: [
    'Portal security headers', 'Main site security headers', 'Documentation security headers',
    'Portal session settings', 'Main site cookie settings', 'Documentation cookie settings',
    'Portal TLS configuration', 'Main site TLS configuration', 'Documentation TLS configuration',
    'Portal deployment configuration', 'Main site deployment configuration', 'Documentation deployment configuration',
    'Portal dependency inventory', 'Main site dependency inventory', 'Documentation dependency inventory',
    'Coverage review', 'Evidence quality review', 'Candidate finding triage',
  ] },
  { title: 'Verification', workers: [
    'Evidence validation', 'Portal header control comparison', 'Session evidence cross-check',
    'TLS baseline comparison', 'Deployment evidence cross-check', 'Dependency evidence cross-check',
    'Coverage reconciliation', 'Final finding review',
  ] },
];
const themes = [
  { id: 'neutral', name: 'Neutral', swatches: ['#f7f7f5', '#d8dbdf', '#242629'] },
  { id: 'slate', name: 'Slate', swatches: ['#f4f6fa', '#5365dc', '#232d45'] },
  { id: 'forest', name: 'Forest', swatches: ['#eef5ef', '#327657', '#203b32'] },
  { id: 'sand', name: 'Sand', swatches: ['#faf4ea', '#a44b34', '#4b352c'] },
];
const savedTheme = localStorage.getItem('kovo-theme');
const legacyPalette = themes.find(item => item.id === savedTheme)?.id ?? (savedTheme === 'midnight' ? 'slate' : undefined);
let theme = legacyPalette ?? 'neutral';
const studioColors = [
  { id: 'porcelain', name: 'Porcelain', description: 'Glacier blue and ultramarine' },
  { id: 'vellum', name: 'Vellum', description: 'Warm ivory and mulberry' },
  { id: 'carbon', name: 'Carbon', description: 'Charcoal top bar and silver' },
  { id: 'delft', name: 'Delft', description: 'Powder blue and ink navy' },
  { id: 'sea-glass', name: 'Sea Glass', description: 'Ice blue and deep teal' },
  { id: 'iris', name: 'Iris', description: 'Pale periwinkle and indigo' },
];
function studioColor(id: string | null) {
  return [...studioColors, ...themes].find(color => color.id === id)?.id;
}
const savedStudioColor = localStorage.getItem('kovo-studio-light');
let studioLight = studioColor(savedStudioColor) ?? legacyPalette ?? 'porcelain';
const visualStyles = {
  studio: 'Soft surfaces, open spacing',
  console: 'Compact rows, precise alignment',
  folio: 'Serif headings, room to read',
};
type VisualStyle = keyof typeof visualStyles;
function validStyle(value: string | null): value is VisualStyle {
  return value !== null && Object.hasOwn(visualStyles, value);
}
const requestedStyle = new URLSearchParams(location.search).get('style');
const savedStyle = localStorage.getItem('kovo-style');
let visualStyle: VisualStyle = validStyle(requestedStyle) ? requestedStyle : validStyle(savedStyle) ? savedStyle : 'studio';
document.documentElement.dataset.style = visualStyle;
const appearances = ['system', 'light', 'dark'] as const;
type Appearance = typeof appearances[number];
const savedAppearance = localStorage.getItem('kovo-appearance');
let appearance: Appearance = appearances.find(option => option === savedAppearance)
  ?? (savedTheme === 'midnight' ? 'dark' : 'system');
let lightPreview = visualStyle === 'studio' ? studioColor(new URLSearchParams(location.search).get('light')) : undefined;
let viewOptionsOpen = false;
const systemDark = window.matchMedia('(prefers-color-scheme: dark)');

function updateAppearance() {
  const dark = !lightPreview && (appearance === 'system' ? systemDark.matches : appearance === 'dark');
  document.documentElement.dataset.scheme = dark ? 'dark' : 'light';
  document.documentElement.dataset.theme = visualStyle === 'studio' && !dark ? lightPreview ?? studioLight : theme;
}

function clearLightPreview() {
  if (!lightPreview) return;
  lightPreview = undefined;
  const url = new URL(location.href);
  url.searchParams.delete('light');
  history.replaceState(null, '', url);
}

systemDark.addEventListener('change', () => {
  const oldScheme = document.documentElement.dataset.scheme;
  updateAppearance();
  const picker = document.getElementById('palette-options');
  if (picker && oldScheme !== document.documentElement.dataset.scheme) {
    const hadFocus = picker.contains(document.activeElement);
    picker.innerHTML = paletteOptions();
    if (hadFocus) picker.querySelector<HTMLElement>('button')?.focus();
  }
});
updateAppearance();
const layouts = {
  workspace: { name: 'Workspace', description: 'Balanced workflow and transcript', columns: [1, 2, 1], nodeWidth: 196, gap: 31, rowHeight: 38 },
  canvas: { name: 'Canvas', description: 'Larger worker graph and a narrower transcript', columns: [1, 2, 1], nodeWidth: 211, gap: 32, rowHeight: 42 },
  review: { name: 'Review', description: 'Wide chat and transcript pane', columns: [1, 1, 1], nodeWidth: 196, gap: 31, rowHeight: 37 },
};
type Layout = keyof typeof layouts;
const savedLayout = localStorage.getItem('kovo-layout') as Layout | null;
let layout: Layout = savedLayout && Object.hasOwn(layouts, savedLayout) ? savedLayout : 'workspace';
document.documentElement.dataset.layout = layout;
const navigationStyles = {
  tree: 'Project tree',
  runs: 'Run list',
  rail: 'Icon rail',
  top: 'Top bar',
};
type NavigationStyle = keyof typeof navigationStyles;
const savedNavigation = localStorage.getItem('kovo-navigation') as NavigationStyle | null;
let navigation: NavigationStyle = savedNavigation && Object.hasOwn(navigationStyles, savedNavigation) ? savedNavigation : 'top';
let projectExpanded = true;
document.documentElement.dataset.navigation = navigation;
let zoom: number | undefined;

function graphGeometry() {
  const style = layouts[layout];
  const padding = 20;
  const columnWidth = style.nodeWidth + 33;
  const startY = 139;
  const routeY = 78;
  const forkY = 102;
  let x = padding;
  const lanes = phases.map((phase, index) => {
    const count = style.columns[index];
    const width = count * columnWidth + 12;
    const rowCount = Math.ceil(phase.workers.length / count);
    const joinY = startY + (rowCount - 1) * style.rowHeight + 28;
    const lane = { x, width, count, rowCount, joinY, input: x + 6, output: x + width - 6 };
    x += width + style.gap;
    return lane;
  });
  return {
    ...style, lanes, startY, routeY, forkY, columnWidth,
    width: x - style.gap + padding,
    height: Math.max(...lanes.map(lane => lane.joinY)) + 30,
  };
}

let dockOpen = localStorage.getItem('kovo-run-pane') !== 'closed';
let dockTab: 'coordinator' | 'worker' = 'coordinator';
let coordinatorDraft = '';
let coordinatorScroll = 0;
let followCoordinator = true;
let demoRunVersion = 0;
const threadView = new Map<string, { scroll: number; evidenceOpen: boolean }>();
let workerQuery = '';
let searchOpen = false;
let searchIndex = 0;
type GraphMode = 'overview' | 'workers';
let graphMode: GraphMode = 'overview';
let scopeReviewOpen = false;
let scopeReturnMode: GraphMode | undefined;
let selectedPhase: number | undefined;
let announcement = '';
type WorkerRef = [phase: number, worker: number];
const workerRefs: WorkerRef[] = phases.flatMap((phase, index) =>
  phase.workers.map((_, worker): WorkerRef => [index, worker]),
);
const workerName = ([phase, worker]: WorkerRef) => phases[phase].workers[worker];

function matchingWorkers() {
  const query = workerQuery.trim().toLowerCase();
  return workerRefs.filter(ref => {
    const name = workerName(ref);
    return name.toLowerCase().includes(query) || (graphLabels[name] ?? '').toLowerCase().includes(query);
  });
}

const slug = (value: string) => value.toLowerCase().replace(/[^a-z0-9]+/g, '-');
const workerHash = (ref: WorkerRef) => `#worker=${slug(phases[ref[0]].title)}/${slug(workerName(ref))}`;

function setWorkerLocation(ref?: WorkerRef) {
  const hash = ref ? workerHash(ref) : '';
  if (location.hash !== hash) history.pushState(null, '', `${location.pathname}${location.search}${hash}`);
}

function selectWorker(ref: WorkerRef) {
  if (scopeReviewOpen) scopeReturnMode = graphMode;
  thread = ref;
  scopeReviewOpen = false;
  dockOpen = true;
  dockTab = 'worker';
  tab = 'Run';
  graphMode = 'workers';
  searchOpen = false;
  workerQuery = '';
}



function workerNote(phase: number, index: number): string {
  if (phase === 0) return [
    'Imported the project seed inventory. The primary website, customer portal, and documentation were listed as first-party assets.',
    'Compared the seed inventory with the project ownership records. Candidate hosts still need user approval.',
    'Matched the customer portal to the project inventory and linked its prepared configuration records.',
    'Identified the documentation host. Its prepared evidence bundle is incomplete.',
    'Matched the supplied service catalog to the host inventory.',
    'Consolidated duplicate entries and retained the source references.',
    'Flagged the externally hosted help center for separate scope review.',
    'Prepared four candidate hosts for scope review, with the third-party help center unchecked by default.',
  ][index];
  if (phase === 1 && index === 0) return 'The portal configuration fixture was missing the expected security header. Recorded a candidate finding for verification.';
  if (phase === 1 && index === 15) return 'Compared the approved host list with the available evidence. The documentation bundle was incomplete.';
  if (phase === 2 && index < 2) return 'Checked the portal fixture against a prepared control fixture. The expected header was present on the control and absent from the portal sample.';
  return `Reviewed the prepared records for ${phases[phase].workers[index].toLowerCase()}. Recorded the available evidence and its limitations for the coordinator.`;
}
const graphLabels: Record<string, string> = {
  'Documentation security headers': 'Docs security headers',
  'Documentation cookie settings': 'Docs cookie settings',
  'Documentation TLS configuration': 'Docs TLS configuration',
  'Main site TLS configuration': 'Site TLS configuration',
  'Portal deployment configuration': 'Portal deploy settings',
  'Main site deployment configuration': 'Site deploy settings',
  'Documentation deployment configuration': 'Docs deploy settings',
  'Portal dependency inventory': 'Portal dependencies',
  'Main site dependency inventory': 'Site dependencies',
  'Documentation dependency inventory': 'Docs dependencies',
  'Portal header control comparison': 'Header baseline check',
  'Session evidence cross-check': 'Session cross-check',
  'Deployment evidence cross-check': 'Deployment cross-check',
  'Dependency evidence cross-check': 'Dependency cross-check',
};
const workerTotal = phases.reduce((total, phase) => total + phase.workers.length, 0);
const icons = {
  search: '<circle cx="8.5" cy="8.5" r="5.7"/><path d="m13 13 4 4"/>',
  sidebar: '<rect x="2.2" y="3.5" width="15.6" height="13" rx="2.4"/><path d="M12 4v12"/>',
  workflow: '<rect x="2.5" y="3" width="5" height="5" rx="1.2"/><rect x="12.5" y="12" width="5" height="5" rx="1.2"/><path d="M5 8v4a2.5 2.5 0 0 0 2.5 2.5h5"/>',
  document: '<path d="M5 2.4h7L16 6v11a.8.8 0 0 1-.8.8H5a1 1 0 0 1-1-1V3.4a1 1 0 0 1 1-1ZM11.8 2.6V6H16M7 10h6m-6 3h4"/>',
  chat: '<path d="M5 3.5h10a2.6 2.6 0 0 1 2.6 2.6v6A2.6 2.6 0 0 1 15 14.7H9l-4.8 3v-3.2A2.5 2.5 0 0 1 2.4 12V6A2.6 2.6 0 0 1 5 3.5Z"/>',
  settings: '<path d="M3 6h3m5 0h6M3 14h7m5 0h2"/><circle cx="8.5" cy="6" r="2.5"/><circle cx="12.5" cy="14" r="2.5"/>',
  folder: '<path d="M2.4 6V4.8c0-1 .7-1.6 1.7-1.6h3.5l2 2h6.3c1 0 1.7.7 1.7 1.7v7.8c0 1-.7 1.8-1.7 1.8H4.1c-1 0-1.7-.8-1.7-1.8V6Z"/>',
  shield: '<path d="M10 2.2 16.8 5v4.5c0 3.5-2.4 6.2-6.8 8.5-4.4-2.3-6.8-5-6.8-8.5V5L10 2.2Z"/><path d="m6.8 9.9 2.2 2.2 4.4-4.5"/>',
  globe: '<circle cx="10" cy="10" r="7.3"/><ellipse cx="10" cy="10" rx="3.1" ry="7.3"/><path d="M3 10h14"/>',
  external: '<path d="M10 3.6h6.4V10M16 4l-7 7M7.5 4H5a1.8 1.8 0 0 0-1.8 1.8v9.1A1.8 1.8 0 0 0 5 16.7h9.1a1.8 1.8 0 0 0 1.8-1.8v-2.5"/>',
};
const icon = (name: keyof typeof icons) => `<svg class="icon icon-${name}" aria-hidden="true" viewBox="0 0 20 20" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${icons[name]}</svg>`;
const brandMark = '<svg class="brand-mark" aria-hidden="true" viewBox="0 0 24 26" fill="currentColor"><path fill-rule="evenodd" d="M12 .8 22 4.6v8.1c0 5.8-4.5 9.9-10 12.4C6.5 22.6 2 18.5 2 12.7V4.6L12 .8Zm0 4.2L6.4 7.2v5.5c0 3.3 2.4 6 5.6 8v-4.2c-1.5-1.2-2.3-2.5-2.3-4.1V9.5l5.5-2.2L12 5Zm2 7.8v6.4c2.3-1.9 3.6-4.1 3.6-6.5v-3l-7 2.8v1.8l3.4-1.5Z"/></svg>';
const app = document.querySelector<HTMLDivElement>('#app')!;
let stage: Stage = 'review';
let firstResult: number | undefined;
let approved = hosts.filter(host => !host.thirdParty).map(host => host.name);
let selection = [...approved];
let paused = false;
let partial = false;
let tab = 'Run';
let thread: WorkerRef | undefined;
let runMenuOpen = false;
let modelOpen = false;
let modelConnected = false;
let goal = 'Review the Northstar website and its related hosts.';
let revisions = 0;
const messages: { person: string; text: string }[] = [
  { person: 'You', text: goal },
  { person: 'Coordinator', text: 'Discovery is complete. I found four candidate hosts, including a third-party help center. Choose which hosts to include before I start analysis.' },
];
const esc = (value: string) => value.replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
const note = (value: string) => {
  messages.push({ person: 'Coordinator', text: value });
  followCoordinator = true;
};
const runStatus = () => partial ? 'Stopped' : paused ? 'Paused' : ({ discover: 'Ready for discovery', review: 'Awaiting scope approval', analyze: 'Analysis', verify: 'Verification', done: 'Complete' })[stage];
type WorkerState = 'Queued' | 'Running' | 'Paused' | 'Complete' | 'Skipped';

function assignedHost(phase: number, worker: number) {
  const name = workerName([phase, worker]);
  if (phase === 1) {
    if (name.startsWith('Portal ')) return hosts[1].name;
    if (name.startsWith('Main site ')) return hosts[0].name;
    if (name.startsWith('Documentation ')) return hosts[2].name;
  }
  if (phase === 2 && worker < 2) return hosts[1].name;
}

function availableWorkers(phase: number) {
  return phases[phase].workers.flatMap((_, index) => {
    const host = assignedHost(phase, index);
    return !host || approved.includes(host) ? [index] : [];
  });
}

function artifactName(phase: number, worker: number) {
  if (phase === 0) return 'inventory-summary.md';
  if (phase === 1 && worker === 0) return 'portal-headers-review.md';
  return phase === 1 ? 'analysis-notes.md' : 'verification-result.md';
}

function paletteOptions() {
  const current = document.documentElement.dataset.theme;
  const standard = themes.map(item => `<button data-action="theme:${item.id}" aria-pressed="${current === item.id}"><span class="swatches" aria-hidden="true">${item.swatches.map(color => `<i style="background:${color}"></i>`).join('')}</span><span>${item.name}</span><span class="theme-check" aria-hidden="true">${current === item.id ? '✓' : ''}</span></button>`).join('');
  if (visualStyle !== 'studio' || document.documentElement.dataset.scheme === 'dark') {
    return `<div class="view-option-label">Palette</div>${standard}`;
  }
  const original = themes.find(item => item.id === current);
  return `<div class="view-option-label">Light palette</div><div class="color-samples" role="group" aria-label="Studio light palettes">
    ${studioColors.map(item => `<button data-action="theme:${item.id}" aria-label="${item.name}" title="${item.description}" aria-pressed="${current === item.id}"><span class="palette-sample" data-sample="${item.id}" aria-hidden="true"><i class="sample-bar"></i><i class="sample-sheet"></i><i class="sample-chat"></i></span><span>${item.name}</span></button>`).join('')}
    </div><details class="standard-palettes"><summary>More palettes${original ? ` · ${original.name}` : ''}</summary>${standard}</details>`;
}

function render() {
  const previousWorker = app.querySelector<HTMLElement>('[data-pane-key]');
  const previousKey = previousWorker?.dataset.paneKey;
  if (previousWorker && previousKey?.startsWith(`${demoRunVersion}:`)) {
    threadView.set(previousKey, {
      scroll: previousWorker.querySelector('.thread-timeline')?.scrollTop ?? 0,
      evidenceOpen: previousWorker.querySelector('details')?.open ?? false,
    });
  }
  const previousMessages = app.querySelector('.coordinator-messages');
  if (previousMessages && !followCoordinator) coordinatorScroll = previousMessages.scrollTop;
  const phaseIndex = ['discover', 'review', 'analyze', 'verify', 'done'].indexOf(stage);
  const editingScope = scopeReviewOpen && !paused;
  const reviewingFirstScope = stage === 'review';
  const analysisActive = availableWorkers(1).slice(0, 2);
  const verificationActive = availableWorkers(2).slice(0, 2);
  const states = phases.map((phase, index): WorkerState[] => {
    return phase.workers.map((_, worker) => {
      if (phaseIndex < index + 1) return 'Queued';
      const host = assignedHost(index, worker);
      if (host && !approved.includes(host)) return 'Skipped';
      if (index === 0 || phaseIndex > index + 1 || (index === 1 && firstResult === worker)) return 'Complete';
      const activeWorkers = index === 1 ? analysisActive : verificationActive;
      return activeWorkers.includes(worker) ? (paused ? 'Paused' : 'Running') : 'Queued';
    });
  });
  const workerChat = thread && dockTab === 'worker' && dockOpen ? (() => {
    const [phase, worker] = thread;
    const workerState = states[phase][worker];
    const waiting = workerState === 'Queued' || workerState === 'Skipped';
    const running = workerState === 'Running' || workerState === 'Paused';
    const name = phases[phase].workers[worker];
    const artifact = artifactName(phase, worker);
    const time = (minutes: number) => `09:${String(12 + phase * 15 + (worker % 6) + minutes).padStart(2, '0')}`;
    const classifiedThirdParty = phase === 0 && worker === 6;
    const ownershipRecords = phase === 0 && worker === 1;
    const inventoryArtifact = classifiedThirdParty || ownershipRecords;
    const result = workerNote(phase, worker);
    return `<div class="thread rich-thread">
      <div class="thread-summary">
        <div class="thread-title"><h2>${name}</h2><button class="thread-close" data-action="dismiss" aria-label="Close worker thread">×</button></div>
        <div class="thread-state"><span>${phases[phase].title}</span><span class="thread-meta-dot">·</span><i class="${workerState.toLowerCase()}"></i>${workerState}${workerState === 'Complete' ? '<span class="thread-meta-dot">·</span><span>4 min</span>' : ''}</div>
        ${workerState === 'Complete' ? `<div class="thread-outcome"><span>Outcome</span><p>${classifiedThirdParty ? 'One vendor-managed host flagged for scope review.' : esc(result)}</p></div>` : ''}
      </div>
      <div class="thread-timeline" aria-label="Worker conversation">
        <article class="thread-entry"><span class="thread-avatar coordinator-avatar" aria-hidden="true">${brandMark}</span><div class="entry-content"><div class="entry-meta"><strong>Coordinator</strong><time>${time(0)}</time></div>
        <div class="chat-bubble">${classifiedThirdParty ? 'Check which candidate hosts are operated by Northstar. Flag any vendor-managed service before scope approval.' : ownershipRecords
          ? 'Compare the project ownership records with the discovered Northstar domains before scope review.'
          : `Review the supplied records for <strong>${name.toLowerCase()}</strong> and report the evidence and coverage gaps.`}</div></div></article>
        ${waiting ? `<div class="thread-event">${workerState === 'Skipped' ? 'Asset outside the approved scope' : 'Waiting to start'}</div>` : `
        <article class="thread-entry"><span class="thread-avatar worker-avatar" aria-hidden="true">${icon('workflow')}</span><div class="entry-content"><div class="entry-meta"><strong>Worker</strong><time>${time(1)}</time></div>
        <div class="chat-bubble">${classifiedThirdParty ? 'The ownership inventory lists three Northstar hosts. The support directory lists <code>help.vendor.example</code> under an external provider.' : ownershipRecords
          ? 'The project ownership inventory lists the primary site, customer portal, and documentation as first-party assets.'
          : 'Opened the prepared project records linked to this assignment.'}</div>
        ${running ? '' : `        <details class="thread-artifact"><summary><span class="artifact-icon">${icon('document')}</span><span><strong>${artifact}</strong><small>${classifiedThirdParty ? '4 host records' : ownershipRecords ? '3 ownership records' : 'Prepared evidence'} · Markdown</small></span></summary>
        ${inventoryArtifact ? `<ul>${hosts.filter(host => classifiedThirdParty || !host.thirdParty).map(host => `<li><code>${host.name}</code><span>${host.thirdParty ? 'Third party' : 'First party'}</span></li>`).join('')}</ul>` : `<p>${esc(result)}</p>`}</details>`}</div></article>
        ${running ? `<div class="thread-event">${paused ? 'Assignment paused' : 'Assignment in progress'}</div>` : `
        <article class="thread-entry"><span class="thread-avatar worker-avatar" aria-hidden="true">${icon('workflow')}</span><div class="entry-content"><div class="entry-meta"><strong>Worker</strong><time>${time(4)}</time></div>
        <div class="chat-bubble">${classifiedThirdParty ? 'I left the help center unchecked in the proposed scope. Its ownership is recorded in the inventory.' : 'I sent the evidence summary and its limitations to the coordinator.'}</div></div></article>
        <div class="thread-event"><span aria-hidden="true">✓</span> Result sent to coordinator</div>`}`}
      </div>
      <div class="thread-footer">${scopeReturnMode
        ? '<button data-action="return-scope">← Return to scope review</button>'
        : '<button data-action="dock:coordinator">Coordinator chat</button>'}<button data-action="copy-link">Copy link</button></div>
    </div>`;
  })() : '';
  const coordinatorChat = `<section class="coordinator-chat" aria-label="Coordinator chat">
    <div class="coordinator-messages" aria-label="Conversation">
      ${messages.map(message => message.person === 'You'
        ? `<article class="coordinator-message coordinator-user"><strong>You</strong><p>${esc(message.text)}</p></article>`
        : `<article class="coordinator-message coordinator-reply"><span class="thread-avatar coordinator-avatar" aria-hidden="true">${brandMark}</span><div><strong>Coordinator</strong><p>${esc(message.text)}</p></div></article>`).join('')}
      ${stage === 'review' && !paused ? '<div class="chat-scope-action"><button data-action="gate">Review discovered hosts <span aria-hidden="true">→</span></button></div>' : ''}
      ${stage === 'discover' ? '<section class="scope"><h2>Authorize discovery</h2><p>Kovo Hunter will review a prepared inventory for the project’s seed domain in this demo.</p><button class="primary" data-action="discover">Consent and discover</button></section>' : ''}
    </div>
    <form id="chat"><input name="message" aria-label="Message the coordinator" placeholder="Message coordinator…" autocomplete="off" value="${esc(coordinatorDraft)}" required><button class="primary" aria-label="Send message">↑</button></form>
  </section>`;
  const geometry = graphGeometry();
  const graphScale = zoom ?? 1;
  const phaseStates = phases.map((_, index) => {
    const active = phaseIndex === index + 1 && index > 0;
    const started = phaseIndex >= index + 1;
    const complete = started && (index === 0 || phaseIndex > index + 1);
    const status = complete ? 'Complete' : active ? (paused ? 'Paused' : 'In progress')
      : index === 1 && stage === 'review' ? 'Waiting for scope' : 'Queued';
    const done = states[index].filter(state => state === 'Complete').length;
    const running = states[index].filter(state => state === 'Running' || state === 'Paused').length;
    const queued = states[index].filter(state => state === 'Queued').length;
    return { active, started, complete, status, done, running, queued };
  });
  const matches = matchingWorkers();
  const hasQuery = workerQuery.trim().length > 0;
  const showResults = searchOpen && hasQuery;
  const resultId = showResults && matches.length ? `worker-result-${searchIndex}` : '';
  const canReview = stage === 'review' && !paused;
  const gateLabel = stage === 'review' ? 'Review scope' : 'Scope approval';
  const gateDetail = stage === 'discover' ? 'No hosts found yet' : stage === 'review'
    ? `${hosts.length} hosts · ${hosts.filter(host => host.thirdParty).length} third-party`
    : `${approved.length} approved hosts`;
  const emphasizedPhase = thread?.[0] ?? selectedPhase;
  const groups = phases.map((phase, index) => {
    const { active, started, complete, status, done, running, queued } = phaseStates[index];
    const lane = geometry.lanes[index];
    const count = complete ? `${done} complete` : active
      ? [running ? `${running} ${paused ? 'paused' : 'running'}` : '', done ? `${done} complete` : '', queued ? `${queued} queued` : ''].filter(Boolean).join(' · ')
      : `${phase.workers.length} queued`;
    return `<section class="dag-phase ${active ? 'active' : ''} ${started ? '' : 'phase-queued'} ${emphasizedPhase === index ? 'phase-selected' : ''}" style="left:${lane.x}px;width:${lane.width}px">
      <button class="dag-phase-head" data-action="phase:${index}" aria-label="${phase.title}, ${status}, ${phase.workers.length} workers">
        <span class="phase-name"><strong>${phase.title}</strong><span class="phase-status ${complete ? 'is-complete' : active ? 'is-active' : ''}"><i></i>${status}</span></span><small>${count}</small>
      </button>
      ${phase.workers.map((worker, workerIndex) => {
        const selected = thread?.[0] === index && thread[1] === workerIndex;
        const workerState = states[index][workerIndex];
        const returned = index === 1 && firstResult === workerIndex && workerState === 'Complete';
        const match = !hasQuery || matches.some(([phase, item]) => phase === index && item === workerIndex);
        const column = Math.floor(workerIndex / lane.rowCount);
        const row = workerIndex % lane.rowCount;
        const nodeX = 22 + column * geometry.columnWidth;
        const nodeY = geometry.startY + row * geometry.rowHeight;
        return `<button class="dag-worker ${workerState.toLowerCase()} ${returned ? 'has-result' : ''} ${selected ? 'current-worker' : ''} ${match ? '' : 'dim-node'}" style="left:${nodeX}px;top:${nodeY - 15}px;width:${geometry.nodeWidth}px" data-action="worker:${index}:${workerIndex}" aria-pressed="${selected}" aria-label="${worker}, ${workerState}" title="${worker} · ${returned ? 'Evidence returned' : workerState}"><span>${graphLabels[worker] ?? worker}</span><small class="worker-status" aria-hidden="true">${({ Complete: '✓', Running: '', Paused: 'Ⅱ', Queued: '', Skipped: '–' })[workerState]}</small></button>`;
      }).join('')}</section>`;
  }).join('');
  const { routeY, forkY, startY, rowHeight, columnWidth, nodeWidth } = geometry;
  const gateX = (geometry.lanes[0].output + geometry.lanes[1].input) / 2;
  const wires = geometry.lanes.map((lane, index) => {
    const phase = phases[index];
    const next = geometry.lanes[index + 1];
    const state = phaseStates[index];
    const rightmostInputRail = lane.x + 12 + (lane.count - 1) * columnWidth;
    const firstOutputRail = lane.x + 22 + nodeWidth + 9;
    const trunk = `<path d="M${lane.input} ${routeY} V${forkY - 5} Q${lane.input} ${forkY} ${lane.input + 5} ${forkY} H${rightmostInputRail} M${firstOutputRail} ${lane.joinY} H${lane.output - 5} Q${lane.output} ${lane.joinY} ${lane.output} ${lane.joinY - 5} V${routeY}"/>`;
    const sections = Array.from({ length: lane.count }, (_, column) => {
      const rowCount = Math.min(lane.rowCount, phase.workers.length - column * lane.rowCount);
      const left = lane.x + 22 + column * columnWidth;
      const right = left + nodeWidth;
      const inRail = left - 10;
      const outRail = right + 9;
      const lastY = startY + (rowCount - 1) * rowHeight;
      const branches = Array.from({ length: rowCount }, (_, row) => {
        const y = startY + row * rowHeight;
        const worker = column * lane.rowCount + row;
        const refSelected = thread?.[0] === index && thread[1] === worker;
        const workerState = states[index][worker];
        if (refSelected) {
          return `<path class="trace-selected" d="M${lane.input} ${routeY} V${forkY} H${inRail} V${y} H${left} M${right} ${y} H${outRail} V${lane.joinY} H${lane.output} V${routeY}"/>`;
        }
        const edgeState = workerState === 'Running' ? 'trace-running' : workerState === 'Complete' ? 'trace-complete' : 'trace-idle';
        return `<path class="${edgeState}" d="M${inRail} ${y} H${left} M${right} ${y} H${outRail}"/>`;
      }).join('');
      return `<path d="M${inRail} ${forkY} V${lastY} M${outRail} ${startY} V${lane.joinY}"/>${branches}`;
    }).join('');
    const handoff = next && index === 0
      ? `<path class="trace-handoff ${state.started ? 'trace-complete' : 'trace-idle'}" d="M${lane.output} ${routeY} H${gateX - 10}"/><path class="trace-handoff ${phaseStates[1].started ? 'trace-complete' : 'trace-idle'}" d="M${gateX + 10} ${routeY} H${next.input - 2}" marker-end="url(#phase-arrow)"/>`
      : next ? `<path class="trace-handoff ${phaseStates[index + 1].started ? 'trace-complete' : 'trace-idle'}" d="M${lane.output} ${routeY} H${next.input - 2}" marker-end="url(#phase-arrow)"/>` : '';
    return `${handoff}<g class="trace-phase ${state.started ? 'trace-started' : 'trace-unstarted'}">${trunk}${sections}<circle class="trace-port" cx="${lane.input}" cy="${routeY}" r="3.3"/><circle class="trace-port" cx="${lane.output}" cy="${routeY}" r="3.3"/><circle class="trace-merge" cx="${lane.output}" cy="${lane.joinY - 5}" r="2.2"/></g>`;
  }).join('');

  const phaseRail = `<div class="phase-rail"><ol class="phase-track" aria-label="Run phases">
    ${phases.map((phase, index) => {
      const { status, done, running, queued, active, complete } = phaseStates[index];
      const progress = active ? [running && `${running} ${paused ? 'paused' : 'running'}`, done && `${done} complete`, queued && `${queued} queued`].filter(Boolean).join(' · ') : status;
      const marks = states[index].map(state => `<i class="mark-${state.toLowerCase()}"></i>`).join('');
      return `<li><button class="rail-node" data-action="phase:${index}" aria-label="${phase.title}, ${progress}, ${phase.workers.length} workers. Open trace">
        <span class="phase-caption"><span class="phase-symbol ${complete ? 'finished' : active ? 'active' : ''}" aria-hidden="true"></span><strong>${phase.title}</strong></span>
        <span class="phase-measure"><b>${phase.workers.length}</b> workers</span><span class="worker-marks" aria-hidden="true">${marks}</span>
        <small class="phase-note">${progress}</small></button></li>`;
    }).join('')}</ol>
    ${canReview && !editingScope ? `<button class="scope-decision" data-action="gate" aria-expanded="false"><span class="decision-icon">${icon('shield')}</span><span class="decision-copy"><strong>Scope approval</strong><small>${hosts.length} hosts discovered · ${hosts.filter(host => host.thirdParty).length} third-party service</small></span><span class="decision-action">Review scope <span aria-hidden="true">→</span></span></button>` : ''}
  </div>`;
  const inventoryHeading = editingScope
    ? (reviewingFirstScope ? 'Review discovered hosts' : 'Narrow approved scope')
    : 'Discovery inventory';
  const inventory = stage === 'discover'
    ? '<section class="inventory-empty"><h2>Discovery inventory</h2><p>Discovered hosts will appear here after discovery.</p><button class="primary" data-action="dock:coordinator">Open discovery setup</button></section>'
    : `<section class="inventory-section ${editingScope ? 'scope-review' : ''}" aria-labelledby="inventory-title">
        <div class="overview-section-heading"><div><h2 id="inventory-title" tabindex="-1">${inventoryHeading}</h2>${editingScope ? `<p>${reviewingFirstScope ? 'Include only hosts you own or are authorized to assess.' : 'Remove hosts from this run’s approved scope.'}</p>` : ''}</div><span>${reviewingFirstScope ? `${hosts.length} discovered` : `${approved.length} approved / ${hosts.length} discovered`}</span></div>
        <div class="inventory-table-scroll"><table class="inventory-table">
          <thead><tr>${editingScope ? '<th class="include-col" scope="col"><span class="sr-only">Include</span></th>' : ''}<th scope="col">Host</th><th scope="col">Ownership evidence</th><th scope="col">Scope</th></tr></thead>
          <tbody>${hosts.map(host => {
            const canSelect = reviewingFirstScope || approved.includes(host.name);
            const included = (editingScope ? selection : approved).includes(host.name);
            const scopeLabel = included ? (reviewingFirstScope ? 'Proposed' : 'Approved') : 'Excluded';
            const evidence = host.thirdParty ? 'Vendor directory' : 'Ownership inventory';
            return `<tr data-host="${host.name}">
              ${editingScope ? `<td class="include-col"><input type="checkbox" aria-label="Include ${host.name}" value="${host.name}" ${included ? 'checked' : ''} ${canSelect ? '' : 'disabled'}></td>` : ''}
              <td class="host-cell"><div class="host-identity"><span class="host-icon">${icon(host.thirdParty ? 'external' : 'globe')}</span><span><code>${host.name}</code><small>${host.description}</small></span></div></td>
              <td class="evidence-cell"><button class="inventory-source" data-action="worker:0:${host.thirdParty ? 6 : 1}" aria-label="${evidence} for ${host.name}">${icon('document')}<span>${evidence}</span><span class="source-arrow" aria-hidden="true">↗</span></button></td>
              <td class="scope-cell"><span class="inventory-status ${scopeLabel.toLowerCase()}"><i></i><span>${scopeLabel}</span></span></td>
            </tr>`;
          }).join('')}</tbody>
        </table></div>
        ${editingScope ? `<div class="inventory-actions"><div><span class="scope-count">${selection.length} selected</span><small>Saving records your electronic consent.</small></div><div class="scope-actions"><button data-action="cancel-scope">Cancel</button><button class="primary" data-action="approve" ${reviewingFirstScope && !selection.length ? 'disabled' : ''}>${reviewingFirstScope ? 'Approve scope' : 'Save scope revision'}</button></div></div>` : ''}
      </section>`;
  const overview = `<div class="workflow-overview">${phaseRail}${inventory}</div>`;
  const workerSurface = `<div class="dag-size" style="width:${geometry.width * graphScale}px;height:${geometry.height * graphScale}px">
    <div class="dag-canvas" style="width:${geometry.width}px;height:${geometry.height}px;transform:scale(${graphScale})">
      <svg class="dag-wires" width="${geometry.width}" height="${geometry.height}" aria-hidden="true"><defs><marker id="phase-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M1 1 L5 3 L1 5"/></marker></defs>${wires}</svg>
      ${groups}
      ${stage === 'discover' ? '' : `<button class="worker-scope-gate ${canReview ? 'scope-required' : ''}" style="left:${gateX}px;top:${routeY}px" data-action="gate" title="${gateLabel} · ${gateDetail}" aria-label="${gateLabel}" aria-expanded="${editingScope}"><span>${stage === 'review' ? '!' : '✓'}</span></button>`}
    </div></div>`;
  const searchResults = showResults ? `<div class="worker-results">
    <div class="result-heading" role="status">${matches.length ? `${matches.length} ${matches.length === 1 ? 'worker' : 'workers'} found` : 'No matching workers'}</div>
    <div id="worker-results" role="listbox" aria-label="Matching worker threads">${matches.map((ref, index) => `<div id="worker-result-${index}" role="option" aria-selected="${index === searchIndex}" data-action="worker:${ref[0]}:${ref[1]}"><strong>${workerName(ref)}</strong><small>${phases[ref[0]].title}</small></div>`).join('')}</div>
    ${matches.length ? '<div class="result-shortcuts"><kbd>↑</kbd><kbd>↓</kbd> Select <kbd>Enter</kbd> Open</div>' : ''}
  </div>` : '';
  const graphTools = `<div class="graph-tools">
    <div class="graph-modes" role="group" aria-label="Graph detail">
      <button data-action="graph:overview" aria-pressed="${graphMode === 'overview'}">Overview</button><button data-action="graph:workers" aria-pressed="${graphMode === 'workers'}">Trace <span>${workerTotal}</span></button>
    </div>
    <div class="graph-actions"><div class="worker-search-control"><div class="search-box">${icon('search')}<input id="worker-search" type="text" role="combobox" aria-label="Find a worker thread" aria-expanded="${showResults}" aria-autocomplete="list" ${showResults ? 'aria-controls="worker-results"' : ''} ${resultId ? `aria-activedescendant="${resultId}"` : ''} placeholder="Find worker…" autocomplete="off" value="${esc(workerQuery)}"><kbd aria-hidden="true">/</kbd></div>${searchResults}</div>
      ${graphMode === 'workers' ? `<div class="zoom-controls"><button data-action="zoom:out" aria-label="Zoom out">−</button><button data-action="zoom:fit" aria-label="Fit workflow">${zoom === undefined ? 'Fit' : `${Math.round(graphScale * 100)}%`}</button><button data-action="zoom:in" aria-label="Zoom in">+</button></div>` : ''}
    </div></div>`;
  const traceEvents = `<ol class="trace-events" aria-label="Run events">
    <li><button data-action="gate" ${stage === 'discover' ? 'disabled' : ''}><span class="trace-event-dot ${canReview ? 'event-decision' : 'event-complete'}"></span><span><strong>${stage === 'review' ? 'Scope review' : phaseIndex >= 2 ? 'Scope approved' : 'Discovery pending'}</strong><small>${gateDetail}</small></span></button></li>
    ${phaseIndex >= 2 ? `<li><button data-action="phase:1"><span class="trace-event-dot ${phaseIndex > 2 ? 'event-complete' : 'event-running'}"></span><span><strong>Analysis started</strong><small>${analysisActive.length} initial assignments</small></span></button></li>` : ''}
    ${firstResult !== undefined ? `<li><button data-action="worker:1:${firstResult}"><span class="trace-event-dot event-evidence"></span><span><strong>Evidence returned</strong><small>${workerName([1, firstResult])}</small></span><span class="trace-event-arrow" aria-hidden="true">↗</span></button></li>` : ''}
    ${phaseIndex >= 3 ? '<li><button data-action="phase:2"><span class="trace-event-dot event-running"></span><span><strong>Verification started</strong><small>Fixture checks</small></span></button></li>' : ''}
  </ol>`;
  const lineage = thread ? (() => {
    const [phase, worker] = thread;
    const state = states[phase][worker];
    const host = assignedHost(phase, worker);
    const source = host ?? (phase === 0 ? 'Discovery records' : 'Approved project evidence');
    return `<div class="worker-lineage" aria-label="Selected worker evidence path">
      <div><small>Input</small><code>${source}</code></div><span aria-hidden="true">→</span>
      <div><small>Assignment</small><strong>${workerName(thread)}</strong></div><span aria-hidden="true">→</span>
      <div><small>Evidence</small>${state === 'Complete' ? `<button data-action="trace-evidence">${artifactName(phase, worker)} <span aria-hidden="true">↗</span></button>` : '<span>Awaiting result</span>'}</div><span aria-hidden="true">→</span>
      <div><small>Outcome</small><strong>${state === 'Complete' && phase === 1 && worker === 0 ? 'Candidate finding' : state === 'Complete' ? 'Result recorded' : state}</strong></div>
    </div>`;
  })() : '';
  const graphPanel = `<section class="workflow dag" aria-label="Run workflow">
    ${graphMode === 'workers' ? traceEvents : ''}
    <div class="dag-viewport ${graphMode === 'overview' ? 'overview-viewport' : ''}" tabindex="0" aria-label="${graphMode === 'overview' ? 'Run phase overview' : 'Worker graph. Use arrows to navigate workers or drag to pan.'}">
      ${graphMode === 'overview' ? overview : workerSurface}
    </div>
    ${graphMode === 'workers' ? lineage : ''}
    ${graphMode === 'workers' ? `<div class="graph-footer"><span><i class="legend-complete"></i>Complete</span><span><i class="legend-queued"></i>Queued</span>${phaseIndex === 2 || phaseIndex === 3 ? `<span><i class="legend-active"></i>${paused ? 'Paused' : 'In progress'}</span>` : ''}<span class="pan-hint">Drag to pan</span></div>` : ''}
  </section>`;
  const stageAction = paused ? '<button data-action="pause" class="primary">Resume</button>'
    : stage === 'analyze' || stage === 'verify'
      ? `<button class="primary" data-action="advance">${stage === 'analyze' ? (firstResult === undefined ? 'Show first result' : 'Finish demo analysis') : 'Finish demo verification'}</button>`
      : '';
  const paneKey = thread ? `${demoRunVersion}:${workerHash(thread)}` : '';
  const showingWorker = Boolean(workerChat);
  const dock = dockOpen ? `<div class="run-dock ${app.querySelector('.run-dock') ? '' : 'pane-opening'}" id="run-dock">
    <div class="run-dock-bar">
      <div class="run-dock-switch" role="group" aria-label="Run conversations">
        <button data-action="dock:coordinator" aria-pressed="${!showingWorker}">Coordinator</button>
        ${thread ? `<button data-action="dock:worker" aria-pressed="${showingWorker}">Worker</button>` : ''}
      </div>
      <button class="collapse-dock" data-action="dock-toggle" aria-label="Collapse run pane" title="Collapse run pane">${icon('sidebar')}</button>
    </div>
    ${showingWorker ? `<section class="graph-thread" aria-label="Worker thread" data-pane-key="${paneKey}">${workerChat}</section>` : coordinatorChat}
  </div>` : '';
  const dockToggle = `<button class="dock-toggle quiet-action" data-action="dock-toggle" aria-label="${dockOpen ? 'Hide run pane' : 'Show run pane'}" aria-expanded="${dockOpen}" ${dockOpen ? 'aria-controls="run-dock"' : ''} title="${dockOpen ? 'Hide run pane' : 'Show run pane'}">${icon('chat')} <span>Chat</span></button>`;
  const viewPicker = `<div class="theme-picker view-picker"><button data-action="view-options" aria-expanded="${viewOptionsOpen}" aria-label="View options">${icon('settings')} View <span aria-hidden="true">⌄</span></button>
    ${viewOptionsOpen ? `<div class="theme-options view-options" aria-label="Navigation, layout, and appearance">
      <div class="view-option-label">Appearance</div>
      <div class="appearance-options" role="group" aria-label="Appearance">${appearances.map(option => `<button data-action="appearance:${option}" aria-pressed="${(lightPreview ? 'light' : appearance) === option}">${option[0].toUpperCase() + option.slice(1)}</button>`).join('')}</div>
      <div id="palette-options">${paletteOptions()}</div>
      <div class="view-option-label">Interface style</div>
      <div class="style-choices" role="group" aria-label="Interface style">${Object.entries(visualStyles).map(([id, description]) => `<button data-action="style:${id}" aria-pressed="${visualStyle === id}"><span class="style-name style-${id}">${id[0].toUpperCase() + id.slice(1)}</span><small>${description}</small><span class="theme-check" aria-hidden="true">${visualStyle === id ? '✓' : ''}</span></button>`).join('')}</div>
      <div class="view-option-label">Navigation</div>
      <div class="navigation-choices" role="group" aria-label="Navigation">
        ${Object.entries(navigationStyles).map(([id, label]) => `<button data-action="navigation:${id}" aria-pressed="${navigation === id}">${label}</button>`).join('')}
      </div>
      <div class="view-option-label">Layout</div>${Object.entries(layouts).map(([id, option]) => `<button data-action="layout:${id}" aria-pressed="${layout === id}"><span class="layout-thumb layout-thumb-${id}" aria-hidden="true"><i></i><i></i><i></i></span><span><strong>${option.name}</strong><small>${option.description}</small></span><span class="theme-check">${layout === id ? '✓' : ''}</span></button>`).join('')}
    </div>` : ''}</div>`;
  const approvedRows = phaseIndex >= 2 ? hosts.filter(host => approved.includes(host.name)) : [];
  const portalFinding = approved.includes(hosts[1].name) && (firstResult === 0 || phaseIndex >= 3);
  const isCompleteReport = stage === 'done';
  const reportStatus = partial ? 'Partial report' : isCompleteReport ? 'Complete report' : 'Report preview';
  const reportHeadline = partial
    ? `Review stopped ${stage === 'analyze' ? 'during analysis' : stage === 'verify' ? 'during verification' : 'before scope approval'}`
    : isCompleteReport ? (portalFinding ? 'One finding confirmed' : 'No findings confirmed')
    : portalFinding ? 'One finding awaiting verification' : 'Assessment in progress';
  const reportSummary = partial
    ? 'This case file records the work completed before the run stopped.'
    : isCompleteReport
      ? portalFinding ? 'A fixture check confirmed a missing security header on the customer portal.' : 'The supplied evidence yielded no confirmed findings in this run.'
      : 'Coverage and findings update as evidence becomes available.';
  const report = `<article class="case-file" aria-labelledby="case-title">
    <header class="case-header">
      <div class="case-metadata"><span>Northstar <span aria-hidden="true">/</span> <code>northstar.example</code></span><span class="case-status ${partial ? 'case-partial' : isCompleteReport ? 'case-complete' : ''}"><i></i>${reportStatus}</span></div>
      <h2 id="case-title">Website review</h2>
      <div class="case-overview"><div><h3>${reportHeadline}</h3><p>${reportSummary}</p></div><dl class="case-totals">
        <div><dt>Approved hosts</dt><dd>${approvedRows.length}</dd></div>
        <div><dt>Confirmed</dt><dd>${portalFinding && isCompleteReport ? 1 : 0}</dd></div>
        <div><dt>Awaiting verification</dt><dd>${portalFinding && !isCompleteReport ? 1 : 0}</dd></div>
      </dl></div>
    </header>
    <section class="case-section case-findings" aria-labelledby="case-findings-title">
      <h3 id="case-findings-title">Findings</h3>
      ${portalFinding ? `<div class="case-finding">
        <div class="case-finding-meta"><span class="case-severity">Low severity</span><span>${isCompleteReport ? 'Confirmed in fixture' : 'Awaiting verification'}</span></div>
        <h4>Missing security header on the customer portal</h4>
        <code>${hosts[1].name}</code>
        <p>${isCompleteReport ? 'The expected header was present in the control fixture and absent from the portal sample.' : 'The analysis worker found the expected header missing from the portal sample.'}</p>
        <p><strong>Remediation</strong> Add the expected header to the portal configuration and check it in the deployment pipeline.</p>
        <button class="case-evidence" data-action="${isCompleteReport ? 'worker:2:0' : 'worker:1:0'}">${icon('document')} ${isCompleteReport ? 'Open evidence validation thread' : 'Open analysis evidence'} <span aria-hidden="true">↗</span></button>
      </div>` : '<p>No findings recorded at this stage.</p>'}
    </section>
    <section class="case-section" aria-labelledby="case-scope-title">
      <h3 id="case-scope-title">Scope and coverage</h3>
      ${approvedRows.length ? `<dl class="case-coverage">${approvedRows.map(host => {
        const coverage = phaseIndex >= 3
          ? host === hosts[2] ? 'Evidence incomplete' : host.thirdParty ? 'Coverage unrecorded' : 'Evidence reviewed'
          : firstResult === 0 && host === hosts[1] ? 'Initial evidence reviewed' : 'Review pending';
        return `<div><dt><code>${host.name}</code></dt><dd>${coverage}</dd></div>`;
      }).join('')}</dl>` : `<p>${phaseIndex < 2 ? 'Scope approval is pending.' : 'No hosts in the current scope.'}</p>`}
      ${phaseIndex >= 2 ? '<p class="case-footnote">Coverage is limited to the supplied evidence and approved hosts.</p>' : ''}
    </section>
  </article>`;
  const currentPage = tab === 'Report' ? 'Report' : 'Workflow';
  const statusClass = stage === 'done' ? 'done' : stage === 'review' || paused ? 'attention' : stage === 'analyze' || stage === 'verify' ? 'running' : '';
  const tabs = ['Workflow', 'Report'];
  const brand = `<div class="brand" aria-label="Kovo Hunter">${brandMark}<span class="rail-text">Kovo Hunter</span></div>`;
  const workspace = '<div class="workspace"><span class="initial" aria-hidden="true">P</span><span class="rail-text">Personal workspace</span></div>';
  const runIndicator = `<i class="nav-state ${statusClass}" aria-hidden="true"></i>`;
  const runLink = `<button class="run-link" data-action="tab:Run" aria-label="Website review" title="Website review">
    ${icon('workflow')}<span class="rail-text">Website review</span>${runIndicator}</button>`;
  const projectLink = `<button class="project nav-project-link" data-action="nav-overview" aria-label="Northstar overview" title="Northstar overview">
    ${icon('folder')}<span class="rail-text">Northstar</span></button>`;
  const newRun = `<button class="new" data-action="new" aria-label="New demo run" title="New demo run">
    <span class="plus-icon" aria-hidden="true">+</span><span class="rail-text">New demo run</span></button>`;
  const settings = `<button class="settings" data-action="model" aria-label="Model settings" title="Model settings">
    ${icon('settings')}<span class="rail-text">Model settings</span></button>`;
  let navContents: string;
  switch (navigation) {
    case 'tree':
      navContents = `${brand}${workspace}<nav class="nav-tree" aria-label="Project tree">
        <div class="rail-label">Projects</div>
        <button class="project nav-project-toggle" data-action="nav-project" aria-expanded="${projectExpanded}" aria-controls="project-runs">
          ${icon('folder')}<span class="rail-text">Northstar</span><span class="project-chevron" aria-hidden="true"></span>
        </button>
        <div class="nav-children" id="project-runs" ${projectExpanded ? '' : 'hidden'}>${runLink}${newRun}</div>
      </nav><div class="nav-narrow-actions">${runLink}${newRun}</div><div class="rail-bottom">${settings}</div>`;
      break;
    case 'runs':
      navContents = `${brand}<div class="nav-run-context">${workspace}${projectLink}</div>
        <nav class="nav-run-list" aria-label="Project runs">
          <div class="nav-run-heading"><span>Runs</span>${newRun}</div>
          <button class="run-link nav-run-record" data-action="tab:Run" aria-label="Website review" title="Website review">
            ${runIndicator}<span class="rail-text"><strong>Website review</strong><small>${runStatus()}</small></span>
          </button>
        </nav><div class="nav-narrow-actions">${runLink}${newRun}</div><div class="rail-bottom">${settings}</div>`;
      break;
    case 'rail':
      navContents = `${brand}<nav class="nav-icon-items" aria-label="Project and run">${projectLink}${runLink}${newRun}</nav><div class="rail-bottom">${settings}</div>`;
      break;
    case 'top':
      navContents = `${brand}<nav class="nav-top-path" aria-label="Project and run">${projectLink}<span class="nav-path-divider" aria-hidden="true">/</span>${runLink}</nav>
        <div class="nav-top-actions">${newRun}${settings}</div>`;
      break;
  }
  app.innerHTML = `<div class="layout">
    <aside class="workspace-nav" aria-label="Workspace navigation">${navContents}</aside>
    <main>
      <header class="run-header">
        <div class="heading"><div class="run-title-group"><h1>Website review</h1><div class="run-meta"><code>northstar.example</code><span class="meta-divider"></span><span class="run-status ${statusClass}"><i></i>${runStatus()}</span>${revisions ? `<span class="meta-divider"></span><span>Revision ${revisions}</span>` : ''}</div></div>
          <div class="run-actions">${phaseIndex > 0 && phaseIndex < 4 && !paused ? '<button class="quiet-action" data-action="pause">Pause</button>' : ''}${phaseIndex >= 2 && phaseIndex < 4 && !paused ? '<button class="quiet-action" data-action="scope">Narrow scope</button>' : ''}${stageAction}
          ${phaseIndex > 0 && phaseIndex < 4 && !paused ? `<div class="theme-picker run-menu"><button class="quiet-action option-trigger" data-action="run-options" aria-expanded="${runMenuOpen}" aria-label="Run actions">···</button>
          ${runMenuOpen ? '<div class="theme-options run-options" aria-label="Run actions"><button data-action="stop">Stop run</button></div>' : ''}</div>` : ''}</div>
        </div>
        <div class="viewbar"><nav class="run-tabs" aria-label="Run views">${tabs.map(label => `<button data-action="tab:${label}" class="${currentPage === label ? 'selected' : ''}" ${currentPage === label ? 'aria-current="page"' : ''}>${label}</button>`).join('')}</nav>
          <div class="viewbar-actions">${currentPage === 'Workflow' ? `${graphTools}${dockToggle}` : ''}${viewPicker}</div>
        </div>
      </header>
      ${currentPage === 'Report' ? report : `<div class="graph-page ${dock ? 'with-dock' : ''}">${graphPanel}${dock}</div>`}
    </main></div>
    <div class="sr-only" role="status">${esc(announcement)}</div>
    ${modelOpen ? `<div class="overlay"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="model-title"><button class="close" data-action="model" aria-label="Close">×</button><h2 id="model-title">Connect a model</h2><p>Preview only. Use a placeholder key.</p><form id="model"><label>Provider<input value="OpenRouter" readonly></label><label>Model<input value="deepseek/deepseek-v4.1-flash-1017"></label><label>API key<input type="password" placeholder="Demo key" autocomplete="off" required></label><button class="primary">Test connection</button>${modelConnected ? '<p role="status">Demo connection successful.</p>' : ''}</form></section></div>` : ''}`;
  const nextWorker = app.querySelector<HTMLElement>('[data-pane-key]');
  const savedThread = nextWorker && threadView.get(nextWorker.dataset.paneKey ?? '');
  if (nextWorker && savedThread) {
    const details = nextWorker.querySelector('details');
    if (details) details.open = savedThread.evidenceOpen;
    const timeline = nextWorker.querySelector('.thread-timeline');
    if (timeline) timeline.scrollTop = savedThread.scroll;
  }
  const nextMessages = app.querySelector('.coordinator-messages');
  if (nextMessages) {
    nextMessages.scrollTop = followCoordinator ? nextMessages.scrollHeight : coordinatorScroll;
    followCoordinator = false;
  }
  if (zoom === undefined) {
    const viewport = app.querySelector('.dag-viewport');
    const canvas = app.querySelector<HTMLElement>('.dag-canvas');
    const size = app.querySelector<HTMLElement>('.dag-size');
    if (viewport && canvas && size) {
      const scale = Math.max(0.78, Math.min(1, (viewport.clientWidth - 1) / geometry.width));
      canvas.style.transform = `scale(${scale})`;
      size.style.width = `${geometry.width * scale}px`;
      size.style.height = `${geometry.height * scale}px`;
    }
  }
}
function searchInput() {
  return app.querySelector<HTMLInputElement>('#worker-search');
}

function workerButton(ref: WorkerRef) {
  return app.querySelector<HTMLButtonElement>(`.dag-worker[data-action="worker:${ref[0]}:${ref[1]}"]`);
}

function revealWorker(ref: WorkerRef, moveFocus: boolean) {
  if (window.matchMedia('(max-width: 760px)').matches && !moveFocus) {
    app.querySelector('.graph-thread')?.scrollIntoView({ block: 'start' });
    return;
  }
  const node = workerButton(ref);
  const viewport = app.querySelector('.dag-viewport');
  if (!node || !viewport) return;
  const bounds = viewport.getBoundingClientRect();
  const rect = node.getBoundingClientRect();
  if (rect.left < bounds.left || rect.right > bounds.right || rect.top < bounds.top || rect.bottom > bounds.bottom) {
    node.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }
  if (moveFocus) node.focus({ preventScroll: true });
}

function syncWorkerLocation() {
  const ref = workerRefs.find(item => workerHash(item) === location.hash);
  if (ref) selectWorker(ref);
  else if (thread && scopeReturnMode) closePane(true);
  else { thread = undefined; dockTab = 'coordinator'; }
  render();
  if (ref) revealWorker(ref, false);
}

function closePane(restoreScope = false) {
  const priorThread = thread;
  const hadScope = scopeReviewOpen;
  thread = undefined;
  dockTab = 'coordinator';
  scopeReviewOpen = false;
  if (priorThread) setWorkerLocation();
  if (restoreScope && scopeReturnMode) {
    graphMode = scopeReturnMode;
    scopeReviewOpen = true;
  }
  scopeReturnMode = undefined;
  return priorThread ? workerButton(priorThread) : hadScope ? app.querySelector<HTMLButtonElement>('[data-action="gate"]') : null;
}

function restoreScroll(viewport: Element | null) {
  if (viewport) app.querySelector('.dag-viewport')?.scrollTo(viewport.scrollLeft, viewport.scrollTop);
}

app.addEventListener('input', event => {
  const input = event.target;
  if (!(input instanceof HTMLInputElement)) return;
  if (input.name === 'message' && input.form?.id === 'chat') {
    coordinatorDraft = input.value;
    return;
  }
  if (input.id !== 'worker-search') return;
  workerQuery = input.value;
  searchOpen = true;
  searchIndex = 0;
  const cursor = input.selectionStart;
  const viewport = app.querySelector('.dag-viewport');
  render();
  restoreScroll(viewport);
  const replacement = searchInput();
  replacement?.focus({ preventScroll: true });
  if (cursor !== null) replacement?.setSelectionRange(cursor, cursor);
});

app.addEventListener('change', event => {
  const input = event.target;
  if (!(input instanceof HTMLInputElement) || input.type !== 'checkbox') return;
  selection = input.checked ? [...selection, input.value] : selection.filter(host => host !== input.value);
  const scope = input.closest('.scope-review');
  const count = scope?.querySelector('.scope-count');
  const approve = scope?.querySelector<HTMLButtonElement>('[data-action="approve"]');
  if (count) count.textContent = `${selection.length} selected`;
  if (approve) approve.disabled = stage === 'review' && selection.length === 0;
  const badge = input.closest('tr')?.querySelector('.inventory-status');
  const status = input.checked ? (stage === 'review' ? 'Proposed' : 'Approved') : 'Excluded';
  if (badge) badge.className = `inventory-status ${status.toLowerCase()}`;
  const label = badge?.querySelector('span');
  if (label) label.textContent = status;
});

app.addEventListener('click', async event => {
  const element = event.target as HTMLElement;
  const target = element.closest<HTMLElement>('[data-action]');
  const viewport = app.querySelector('.dag-viewport');
  if (!target) {
    const dismissOptions = viewOptionsOpen && !element.closest('.view-picker');
    const dismissSearch = searchOpen && !element.closest('.worker-search-control');
    const dismissRunMenu = runMenuOpen && !element.closest('.run-menu');
    if (dismissOptions || dismissSearch || dismissRunMenu) {
      if (dismissOptions) viewOptionsOpen = false;
      if (dismissSearch) searchOpen = false;
      if (dismissRunMenu) {
        runMenuOpen = false;
        app.querySelector('.run-options')?.remove();
        app.querySelector('[data-action="run-options"]')?.setAttribute('aria-expanded', 'false');
      }
      // Native form interactions must retain their DOM and focus.
      if (dismissOptions) app.querySelector('.view-options')?.remove();
      if (dismissSearch) {
        app.querySelector('.worker-results')?.remove();
        const input = searchInput();
        input?.setAttribute('aria-expanded', 'false');
        input?.removeAttribute('aria-controls');
        input?.removeAttribute('aria-activedescendant');
      }
      if (dismissOptions) app.querySelector('[data-action="view-options"]')?.setAttribute('aria-expanded', 'false');
    }
    return;
  }
  const [action, a, b] = target.dataset.action!.split(':');
  if (action === 'trace-evidence' && thread) {
    if (!dockOpen || dockTab !== 'worker') {
      dockOpen = true;
      dockTab = 'worker';
      render();
      restoreScroll(viewport);
    }
    const evidence = app.querySelector<HTMLDetailsElement>('.thread-artifact');
    if (evidence) {
      evidence.open = true;
      evidence.scrollIntoView({ block: 'nearest' });
      evidence.querySelector('summary')?.focus({ preventScroll: true });
    }
    return;
  }
  if (action === 'copy-link' && thread) {
    try {
      await navigator.clipboard.writeText(new URL(workerHash(thread), location.href).href);
      announce('Worker link copied.');
      target.textContent = 'Link copied';
    } catch {
      announce('Copy the worker link from the address bar.');
      target.textContent = 'Copy from address bar';
    }
    return;
  }
  if (!['view-options', 'layout', 'navigation', 'theme', 'appearance'].includes(action)) viewOptionsOpen = false;
  if (action !== 'worker') searchOpen = false;
  if (action !== 'run-options') runMenuOpen = false;
  let reveal: WorkerRef | undefined;
  let moveFocus = false;
  let focusSelector: string | undefined;
  const oldMode = graphMode;
  switch (action) {
    case 'run-options':
      runMenuOpen = !runMenuOpen;
      focusSelector = '[data-action="run-options"]';
      break;
    case 'view-options':
      viewOptionsOpen = !viewOptionsOpen;
      focusSelector = '[data-action="view-options"]';
      break;
    case 'style': {
      if (!validStyle(a)) return;
      if (a !== 'studio') clearLightPreview();
      visualStyle = a;
      updateAppearance();
      document.documentElement.dataset.style = a;
      localStorage.setItem('kovo-style', a);
      const url = new URL(location.href);
      if (url.searchParams.has('style')) {
        url.searchParams.set('style', a);
        history.replaceState(null, '', url);
      }
      focusSelector = '[data-action="view-options"]';
      break;
    }
    case 'navigation':
      if (!Object.hasOwn(navigationStyles, a)) return;
      navigation = a as NavigationStyle;
      localStorage.setItem('kovo-navigation', navigation);
      document.documentElement.dataset.navigation = navigation;
      focusSelector = `[data-action="navigation:${navigation}"]`;
      break;
    case 'nav-project':
      projectExpanded = !projectExpanded;
      focusSelector = '[data-action="nav-project"]';
      break;
    case 'nav-overview':
      closePane();
      tab = 'Run';
      graphMode = 'overview';
      focusSelector = '[data-action="graph:overview"]';
      break;
    case 'layout':
      if (!Object.hasOwn(layouts, a)) return;
      layout = a as Layout;
      document.documentElement.dataset.layout = layout;
      localStorage.setItem('kovo-layout', layout);
      viewOptionsOpen = false;
      zoom = undefined;
      focusSelector = '[data-action="view-options"]';
      break;
    case 'theme': {
      const editingStudioLight = visualStyle === 'studio' && document.documentElement.dataset.scheme === 'light';
      if (editingStudioLight) {
        if (!studioColor(a)) return;
        studioLight = a;
        localStorage.setItem('kovo-studio-light', a);
        if (lightPreview) {
          lightPreview = a;
          const url = new URL(location.href);
          url.searchParams.set('light', a);
          history.replaceState(null, '', url);
        }
      } else {
        if (!themes.some(item => item.id === a)) return;
        localStorage.setItem('kovo-studio-light', studioLight);
        theme = a;
        localStorage.setItem('kovo-theme', a);
      }
      updateAppearance();
      const inGallery = editingStudioLight && studioColors.some(item => item.id === a);
      viewOptionsOpen = inGallery;
      focusSelector = inGallery ? `[data-action="theme:${a}"]` : '[data-action="view-options"]';
      break;
    }
    case 'appearance': {
      const option = appearances.find(item => item === a);
      if (!option) return;
      if (option === 'light' && lightPreview) {
        studioLight = lightPreview;
        localStorage.setItem('kovo-studio-light', studioLight);
      }
      clearLightPreview();
      appearance = option;
      localStorage.setItem('kovo-appearance', option);
      updateAppearance();
      focusSelector = `[data-action="appearance:${option}"]`;
      break;
    }
    case 'graph':
      graphMode = a === 'workers' ? 'workers' : 'overview';
      selectedPhase = undefined;
      focusSelector = `[data-action="graph:${graphMode}"]`;
      break;
    case 'phase':
      selectedPhase = Number(a);
      graphMode = 'workers';
      reveal = [selectedPhase, 0];
      moveFocus = true;
      break;
    case 'tab':
      tab = a === 'Report' ? 'Report' : 'Run';
      if (tab === 'Report') closePane();
      focusSelector = `[data-action="tab:${a}"]`;
      break;
    case 'dock-toggle':
      dockOpen = !dockOpen;
      localStorage.setItem('kovo-run-pane', dockOpen ? 'open' : 'closed');
      focusSelector = '.viewbar [data-action="dock-toggle"]';
      break;
    case 'dock':
      tab = 'Run';
      dockOpen = true;
      dockTab = a === 'worker' && thread ? 'worker' : 'coordinator';
      focusSelector = `[data-action="dock:${dockTab}"]`;
      break;
    case 'worker':
      reveal = [Number(a), Number(b)];
      selectWorker(reveal);
      setWorkerLocation(reveal);
      if (event.detail === 0) focusSelector = '.graph-thread .thread-close';
      else if (target.classList.contains('dag-worker') && !window.matchMedia('(max-width: 760px)').matches) moveFocus = true;
      break;
    case 'gate':
    case 'scope': {
      const wasReviewing = scopeReviewOpen;
      closePane();
      scopeReviewOpen = !paused && (action === 'scope' || stage === 'review');
      if (!wasReviewing) selection = [...approved];
      tab = 'Run';
      graphMode = 'overview';
      focusSelector = '#inventory-title';
      break;
    }
    case 'cancel-scope':
      scopeReviewOpen = false;
      selection = [...approved];
      focusSelector = stage === 'review' ? '.phase-rail [data-action="gate"]' : '[data-action="scope"]';
      break;
    case 'zoom': {
      const width = viewport?.clientWidth ?? graphGeometry().width;
      const scale = zoom ?? Math.max(0.78, Math.min(1, (width - 1) / graphGeometry().width));
      zoom = a === 'fit' ? undefined
        : Math.round(Math.max(0.55, Math.min(1.45, scale + (a === 'in' ? 0.1 : -0.1))) * 100) / 100;
      focusSelector = `[data-action="zoom:${a}"]`;
      break;
    }
    case 'return-scope':
    case 'dismiss': {
      const prior = closePane(true);
      focusSelector = scopeReviewOpen ? '#inventory-title'
        : oldMode === 'overview' && prior?.classList.contains('dag-worker') ? '[data-action="graph:overview"]'
        : prior ? `[data-action="${prior.dataset.action}"]` : '[data-action="graph:overview"]';
      break;
    }
    case 'model': modelOpen = !modelOpen; modelConnected = false; break;
    case 'new':
      closePane(); workerQuery = ''; graphMode = 'overview'; dockOpen = true;
      coordinatorDraft = ''; coordinatorScroll = 0; followCoordinator = true;
      demoRunVersion++; threadView.clear();
      stage = 'discover'; firstResult = undefined; paused = false; partial = false; tab = 'Run';
      goal = 'Review the Northstar website and its related hosts.'; messages.length = 0; revisions = 0;
      approved = hosts.filter(host => !host.thirdParty).map(host => host.name); selection = [...approved]; break;
    case 'discover':
      stage = 'review'; graphMode = 'overview'; scopeReviewOpen = true;
      note('Discovery found four candidate hosts. Review scope to start analysis.');
      focusSelector = '#inventory-title';
      break;
    case 'approve': {
      if (paused || (stage === 'review' && !selection.length)) return;
      approved = [...selection];
      scopeReviewOpen = false;
      if (stage === 'review') {
        stage = 'analyze'; graphMode = 'workers'; selectedPhase = 1;
        announcement = `Scope approved for ${approved.length} hosts. Analysis has started.`;
      } else {
        revisions++;
        announcement = `Scope revision recorded. ${approved.length} hosts remain approved.`;
      }
      note(announcement);
      focusSelector = graphMode === 'workers' ? '[data-action="advance"]' : '#inventory-title';
      break;
    }
    case 'pause':
      paused = !paused; if (!paused) partial = false;
      note(paused ? 'Run paused. Select Resume when you’re ready.' : 'Resumed from the saved phase.'); break;
    case 'stop': closePane(); paused = true; partial = true; tab = 'Report'; note('Run stopped. A partial report is available.'); break;
    case 'advance':
      if (stage === 'analyze' && firstResult === undefined) {
        firstResult = availableWorkers(1)[0];
        const message = `${workerName([1, firstResult])} returned its evidence. Analysis is still in progress.`;
        announce(message);
        note(message);
        focusSelector = '[data-action="advance"]';
      } else if (stage === 'analyze') {
        stage = 'verify';
        selectedPhase = 2;
        note('Analysis is complete. The verification agent will check the prepared evidence.');
      }
      else { closePane(); stage = 'done'; note('Verification finished. The report is ready.'); tab = 'Report'; }
      break;
    default: return;
  }
  render();
  if (oldMode === graphMode && action !== 'layout' && a !== 'fit') restoreScroll(viewport);
  if (reveal) revealWorker(reveal, moveFocus);
  if (focusSelector === '#inventory-title' || (action === 'new' || action === 'dock' || action === 'dock-toggle') && dockOpen && window.matchMedia('(max-width: 760px)').matches) {
    app.querySelector(focusSelector === '#inventory-title' ? '#inventory-title' : '.run-dock')?.scrollIntoView({ block: 'nearest' });
  }
  if (focusSelector) app.querySelector<HTMLElement>(focusSelector)?.focus({ preventScroll: true });
});

function announce(message: string) {
  announcement = message;
  const live = app.querySelector('.sr-only[role="status"]');
  if (live) live.textContent = message;
}

document.addEventListener('keydown', event => {
  const input = searchInput();
  const element = event.target as HTMLElement;
  const viewport = app.querySelector('.dag-viewport');
  const editing = element.matches('input, textarea, [contenteditable="true"]');
  if (event.key === '/' && input && !editing && !modelOpen && !event.metaKey && !event.ctrlKey && !event.altKey) {
    event.preventDefault();
    input.focus();
    input.select();
    return;
  }
  if (event.key === 'Escape') {
    if (!modelOpen && !viewOptionsOpen && !runMenuOpen && !searchOpen && !scopeReviewOpen && (!dockOpen || tab === 'Report')) return;
    event.preventDefault();
    let restore: string;
    if (modelOpen) { modelOpen = false; restore = '[data-action="model"]'; }
    else if (viewOptionsOpen) { viewOptionsOpen = false; restore = '[data-action="view-options"]'; }
    else if (runMenuOpen) { runMenuOpen = false; restore = '[data-action="run-options"]'; }
    else if (searchOpen) { searchOpen = false; workerQuery = ''; restore = '#worker-search'; }
    else if (thread && dockOpen && dockTab === 'worker') {
      const worker = thread;
      closePane(true);
      restore = scopeReviewOpen ? '#inventory-title' : `.dag-worker[data-action="worker:${worker[0]}:${worker[1]}"]`;
    } else if (scopeReviewOpen) {
      scopeReviewOpen = false;
      restore = stage === 'review' ? '.phase-rail [data-action="gate"]' : '[data-action="scope"]';
    } else {
      dockOpen = false;
      localStorage.setItem('kovo-run-pane', 'closed');
      restore = '.viewbar [data-action="dock-toggle"]';
    }
    render();
    restoreScroll(viewport);
    app.querySelector<HTMLElement>(restore)?.focus({ preventScroll: true });
    return;
  }
  if (element === input && input && workerQuery.trim() && ['ArrowDown', 'ArrowUp', 'Enter'].includes(event.key)) {
    const matches = matchingWorkers();
    if (!matches.length) return;
    event.preventDefault();
    if (event.key === 'Enter') {
      const ref = matches[searchIndex];
      selectWorker(ref);
      setWorkerLocation(ref);
      render();
      restoreScroll(viewport);
      revealWorker(ref, false);
      app.querySelector<HTMLElement>('.graph-thread .thread-close')?.focus({ preventScroll: true });
    } else {
      if (searchOpen) searchIndex = (searchIndex + (event.key === 'ArrowDown' ? 1 : -1) + matches.length) % matches.length;
      searchOpen = true;
      render();
      restoreScroll(viewport);
      searchInput()?.focus({ preventScroll: true });
      app.querySelector(`#worker-result-${searchIndex}`)?.scrollIntoView({ block: 'nearest' });
    }
    return;
  }
  const node = element.closest<HTMLElement>('.dag-worker');
  if (!node || !['ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight'].includes(event.key)) return;
  event.preventDefault();
  const [, phaseId, workerId] = node.dataset.action!.split(':');
  const phase = Number(phaseId);
  const worker = Number(workerId);
  const lanes = graphGeometry().lanes;
  const lane = lanes[phase];
  const column = Math.floor(worker / lane.rowCount);
  const row = worker % lane.rowCount;
  let destination: WorkerRef = [phase, worker];
  if (event.key === 'ArrowUp' || event.key === 'ArrowDown') {
    const last = Math.min(lane.rowCount - 1, phases[phase].workers.length - column * lane.rowCount - 1);
    const adjacent = row + (event.key === 'ArrowUp' ? -1 : 1);
    if (adjacent >= 0 && adjacent <= last) destination = [phase, column * lane.rowCount + adjacent];
  } else {
    const offset = event.key === 'ArrowLeft' ? -1 : 1;
    const adjacentColumn = column + offset;
    if (adjacentColumn >= 0 && adjacentColumn < lane.count) destination = [phase, adjacentColumn * lane.rowCount + row];
    else if (lanes[phase + offset]) {
      const adjacent = lanes[phase + offset];
      const nextColumn = offset < 0 ? adjacent.count - 1 : 0;
      destination = [phase + offset, nextColumn * adjacent.rowCount + Math.min(row, adjacent.rowCount - 1)];
    }
  }
  revealWorker(destination, true);
});

window.addEventListener('hashchange', syncWorkerLocation);
app.addEventListener('submit', event => {
  event.preventDefault();
  const form = event.target as HTMLFormElement;
  if (form.id === 'model') { modelConnected = true; render(); return; }
  const value = String(new FormData(form).get('message') ?? '').trim();
  if (!value) return;
  const viewport = app.querySelector('.dag-viewport');
  coordinatorDraft = '';
  messages.push({ person: 'You', text: value });
  if (/^pause\b/i.test(value) && stage !== 'done') { paused = true; note('Paused. Select Resume when you’re ready.'); }
  else if (/^(revise|goal)\s*:/i.test(value) && stage !== 'done') {
    goal = value.replace(/^[^:]+:\s*/, '') || goal;
    revisions++; note('Goal revision recorded. Approved scope still applies.');
  } else note(`Current status: ${runStatus()}. To record a new goal, start your message with “Revise:”.`);
  render();
  restoreScroll(viewport);
  app.querySelector<HTMLInputElement>('#chat input')?.focus({ preventScroll: true });
});
syncWorkerLocation();

let pan: { id: number; x: number; y: number; left: number; top: number; viewport: HTMLElement } | undefined;
app.addEventListener('pointerdown', event => {
  const target = event.target as HTMLElement;
  const viewport = target.closest<HTMLElement>('.dag-viewport');
  if (!viewport || viewport.classList.contains('overview-viewport') || target.closest('button') || event.pointerType === 'touch' || event.button !== 0) return;
  pan = { id: event.pointerId, x: event.clientX, y: event.clientY, left: viewport.scrollLeft, top: viewport.scrollTop, viewport };
  viewport.setPointerCapture(event.pointerId);
  viewport.classList.add('panning');
});
app.addEventListener('pointermove', event => {
  if (pan?.id !== event.pointerId) return;
  pan.viewport.scrollTo(pan.left + pan.x - event.clientX, pan.top + pan.y - event.clientY);
});
for (const eventName of ['pointerup', 'pointercancel', 'lostpointercapture']) {
  app.addEventListener(eventName, () => { pan?.viewport.classList.remove('panning'); pan = undefined; });
}

'use strict';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

const SVG_NS = 'http://www.w3.org/2000/svg';
const GIB = 1024 * 1024 * 1024;

const state = {
  path: '',
  kind: 'missing',
  bytesWritten: 0,
  canceled: false,
  devices: [],
  device: null,
};

const SCREENS = ['screen-home', 'screen-scan', 'screen-results', 'screen-erase', 'screen-done'];

// Which step of Check, Erase, Verify each screen belongs to.
const STEP_FOR = {
  'screen-scan': 'check',
  'screen-results': 'check',
  'screen-erase': 'erase',
  'screen-done': 'verify',
};

if (/Mac/i.test(navigator.userAgent)) {
  document.documentElement.classList.add('is-mac');
}

function show(id) {
  for (const screen of SCREENS) {
    $(screen).hidden = screen !== id;
  }
  for (const step of $('trail').children) {
    if (step.dataset.step === STEP_FOR[id]) step.setAttribute('aria-current', 'step');
    else step.removeAttribute('aria-current');
  }
  window.scrollTo(0, 0);
}

function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function showError(target, error) {
  target.replaceChildren(icon('alert'), el('span', '', String(error)));
  target.hidden = false;
}

function fillNotes(listEl, notes) {
  listEl.replaceChildren();
  for (const text of notes) {
    listEl.append(el('li', '', text));
  }
  listEl.hidden = notes.length === 0;
}

function renderInspect(card, view) {
  card.querySelector('.profile-line').textContent = view.profile_line;
  card.querySelector('.headline').textContent = view.headline;
  fillNotes(card.querySelector('.notes'), view.notes);
  card.hidden = false;
}

function setBusy(button, busyText) {
  button.dataset.label = button.textContent;
  button.disabled = true;
  button.textContent = busyText;
}

function clearBusy(button) {
  button.disabled = false;
  button.textContent = button.dataset.label;
}

// Amounts and time

function formatAmount(gib) {
  if (gib < 0.1) {
    return `${(gib * 1024).toFixed(1)} MiB`;
  }
  return `${gib.toFixed(1)} GiB`;
}

function formatPlainSize(bytes) {
  const tb = bytes / 1e12;
  if (tb >= 1) {
    const shown = tb >= 10 ? tb.toFixed(0) : tb.toFixed(1).replace(/\.0$/, '');
    return `${shown} TB`;
  }
  const gb = bytes / 1e9;
  if (gb >= 1) {
    const shown = gb >= 10 ? gb.toFixed(0) : gb.toFixed(1).replace(/\.0$/, '');
    return `${shown} GB`;
  }
  const mb = Math.max(1, Math.round(bytes / 1e6));
  return `${mb} MB`;
}

function formatSpeed(mibPerS) {
  return `${Number.isFinite(mibPerS) ? mibPerS.toFixed(0) : '0'} MiB/s`;
}

function formatPercent(percent) {
  const capped = Math.min(100, Math.max(0, percent));
  return capped >= 100 ? '100' : capped.toFixed(1);
}

// A rough guess from the pace so far. Shown only once there is enough to go on.
function timeLeft(percent, elapsedSecs) {
  if (percent >= 100) return 'Done';
  if (!(percent >= 0.5) || !(elapsedSecs >= 3)) return 'Working it out';
  const secs = (elapsedSecs * (100 - percent)) / percent;
  if (secs < 45) return 'Under a minute';
  if (secs < 90) return 'About 1 minute';
  if (secs < 3600) return `About ${Math.round(secs / 60)} minutes`;
  // Past an hour, round to the nearest five minutes.
  const totalMinutes = Math.round(secs / 300) * 5;
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  const hourText = `${hours} ${hours === 1 ? 'hour' : 'hours'}`;
  return minutes === 0 ? `About ${hourText}` : `About ${hourText} ${minutes} minutes`;
}

function baseName(path) {
  const parts = String(path).split(/[\\/]/).filter(Boolean);
  return parts.length ? parts[parts.length - 1] : String(path);
}

function parentDir(path) {
  const text = String(path);
  const cut = Math.max(text.lastIndexOf('/'), text.lastIndexOf('\\'));
  return cut > 0 ? text.slice(0, cut) : text;
}

// Block grid: 100 squares

const CELLS = 100;
const GRID_COLUMNS = 25;

function gridCells(grid) {
  if (grid.childElementCount === 0) {
    for (let i = 0; i < CELLS; i += 1) {
      const cell = document.createElement('i');
      cell.style.setProperty('--i', i);
      cell.style.setProperty('--col', i % GRID_COLUMNS);
      grid.append(cell);
    }
  }
  return grid.children;
}

function fillGrid(grid, percent) {
  const capped = Math.min(100, Math.max(0, percent));
  const done = Math.floor(capped);
  const cells = gridCells(grid);
  for (let i = 0; i < CELLS; i += 1) {
    cells[i].className = i < done ? 'on' : i === done ? 'now' : '';
  }
  grid.setAttribute('aria-valuenow', capped.toFixed(0));
}

// Split 100 squares across the counts. Anything above zero gets at least one
// square, so a small amount of leftover data never disappears from the picture.
function shareCells(counts) {
  const total = counts.reduce((sum, n) => sum + n, 0);
  if (total === 0) return counts.map(() => 0);
  const exact = counts.map((n) => (n / total) * CELLS);
  const cells = exact.map((x, i) => (counts[i] > 0 ? Math.max(1, Math.floor(x)) : 0));
  let spare = CELLS - cells.reduce((sum, n) => sum + n, 0);
  const byRemainder = exact
    .map((x, i) => [x - Math.floor(x), i])
    .filter(([, i]) => counts[i] > 0)
    .sort((a, b) => b[0] - a[0]);
  for (let k = 0; spare > 0; k = (k + 1) % byRemainder.length) {
    cells[byRemainder[k][1]] += 1;
    spare -= 1;
  }
  while (spare < 0) {
    cells[cells.indexOf(Math.max(...cells))] -= 1;
    spare += 1;
  }
  return cells;
}

function shareText(count, total) {
  if (total === 0 || count === 0) return '0%';
  const percent = (count / total) * 100;
  if (percent < 1) return 'Under 1%';
  if (count < total && percent > 99) return 'Over 99%';
  return `${Math.round(percent)}%`;
}

const BLOCK_CLASSES = ['structured', 'random', 'fill', 'empty'];

function paintGrid(grid, counts) {
  const cells = gridCells(grid);
  const shares = shareCells(counts);
  const classes = [];
  shares.forEach((n, i) => {
    for (let k = 0; k < n; k += 1) classes.push(`c-${BLOCK_CLASSES[i]}`);
  });
  for (let i = 0; i < CELLS; i += 1) cells[i].className = '';
  grid.classList.add('reveal');
  // Color the squares a beat later so they fill in one after another.
  setTimeout(() => {
    for (let i = 0; i < CELLS; i += 1) cells[i].className = classes[i] || '';
  }, 60);
}

// Home

function metaLine(device) {
  let media = device.kind === 'volume' ? 'volume' : 'disk';
  if (device.solid_state === true) media = 'SSD';
  else if (device.solid_state === false) media = 'hard disk';
  let what = media.charAt(0).toUpperCase() + media.slice(1);
  if (device.internal === true) what = `Internal ${media}`;
  else if (device.internal === false) what = `External ${media}`;
  return `${what}, ${formatPlainSize(device.size_bytes)}`;
}

function deviceIcon(device) {
  if (device.internal === false) return 'external';
  if (device.solid_state === false) return 'hdd';
  return 'drive';
}

function plainDiskName(disk, volumes) {
  const hd = volumes.find((volume) => (volume.volume_name || volume.name) === 'Macintosh HD');
  if (disk.internal === true && hd) return 'Macintosh HD';
  if (disk.volume_name) return disk.volume_name;
  const friendly = volumes.find((volume) => {
    const name = volume.volume_name || volume.name || '';
    return name && !/preboot|recovery|update|^vm$|hardware|xart|iscpreboot/i.test(name);
  });
  if (friendly && /ssd|hdd|nvme|apple|disk image/i.test(disk.name)) {
    return friendly.volume_name || friendly.name;
  }
  return disk.name;
}

function presentRows(devices) {
  const disks = devices.filter((device) => device.kind === 'disk');
  const volumes = devices.filter((device) => device.kind === 'volume');
  const hasInternalDisk = disks.some((device) => device.internal === true);
  const hasExternalDisk = disks.some((device) => device.internal === false);
  const rows = [];
  for (const disk of disks) {
    disk.displayName = plainDiskName(disk, volumes);
    disk.displayMeta = metaLine(disk);
    rows.push(disk);
  }
  for (const volume of volumes) {
    if (volume.internal === true && hasInternalDisk) continue;
    if (volume.internal === false && hasExternalDisk) continue;
    if (disks.length > 0 && volume.internal !== false) continue;
    volume.displayName = volume.volume_name || volume.name;
    volume.displayMeta = metaLine(volume);
    rows.push(volume);
  }
  return rows;
}

function deviceRow(device) {
  const row = document.createElement('li');
  const button = el('button', 'device');
  button.type = 'button';
  button.dataset.node = device.device_node;
  const tile = el('span', 'tile');
  tile.append(icon(deviceIcon(device)));
  const copy = el('span', 'device-copy');
  copy.append(
    el('span', 'device-name', device.displayName || device.name),
    el('span', 'device-meta', device.displayMeta || metaLine(device)),
  );
  button.append(tile, copy, el('span', 'pill', 'Scan'));
  row.append(button);
  return row;
}

function skeletonRow() {
  const row = el('li', 'skeleton');
  row.append(el('i'), el('i'));
  return row;
}

function renderDevices(devices) {
  const list = $('device-list');
  list.replaceChildren();
  for (const device of presentRows(devices)) {
    list.append(deviceRow(device));
  }
}

async function loadDevices() {
  const list = $('device-list');
  $('device-error').hidden = true;
  $('device-empty').hidden = true;
  list.replaceChildren(skeletonRow(), skeletonRow());
  list.setAttribute('aria-busy', 'true');
  try {
    const view = await invoke('list_devices');
    state.devices = view.devices || [];
    if (view.heading && view.heading !== 'Disks') {
      $('device-heading').textContent =
        `Disks on ${view.heading.charAt(0).toLowerCase()}${view.heading.slice(1)}`;
    } else {
      $('device-heading').textContent = 'Disks';
    }
    renderDevices(state.devices);
    $('device-empty').hidden = list.childElementCount > 0;
  } catch (error) {
    list.replaceChildren();
    showError($('device-error'), error);
  } finally {
    list.removeAttribute('aria-busy');
  }
}

$('device-list').addEventListener('click', (event) => {
  const button = event.target.closest('button[data-node]');
  if (!button) return;
  const device = state.devices.find((item) => item.device_node === button.dataset.node);
  if (!device) return;
  openScanConfirm(device);
});

$('btn-refresh-devices').addEventListener('click', () => {
  loadDevices();
});

// Scan

function setScanMode(mode) {
  $('btn-scan-back').hidden = mode !== 'confirm';
  $('scan-confirm').hidden = mode !== 'confirm';
  $('scan-running').hidden = mode !== 'running';
  $('scan-reading').hidden = mode !== 'reading';
}

function openScanConfirm(device) {
  state.device = device;
  state.kind = 'device';
  state.path = device.mount_point || device.device_node;
  const title = device.displayName || device.name;
  $('scan-icon').replaceChildren(icon(deviceIcon(device)));
  $('scan-name').textContent = title;
  $('scan-meta').textContent = device.displayMeta || metaLine(device);
  $('scan-warn').textContent =
    `${title} is about ${formatPlainSize(device.size_bytes)}. A scan can take a long time.`;
  $('scan-error').hidden = true;
  $('btn-scan-start').disabled = false;
  setScanMode('confirm');
  show('screen-scan');
}

function updateScan(progress) {
  $('scan-percent').textContent = formatPercent(progress.percent);
  fillGrid($('scan-grid'), progress.percent);
  $('scan-read').textContent =
    `${formatAmount(progress.gib_read)} of ${formatAmount(progress.gib_total)}`;
  $('scan-speed').textContent = formatSpeed(progress.mib_per_s);
  $('scan-left').textContent = timeLeft(progress.percent, progress.elapsed_secs);
}

listen('scan-progress', (event) => updateScan(event.payload));

$('btn-scan-back').addEventListener('click', () => {
  show('screen-home');
});

$('btn-scan-start').addEventListener('click', async () => {
  const device = state.device;
  if (!device) return;
  $('scan-error').hidden = true;
  $('btn-scan-stop').disabled = false;
  $('btn-scan-stop').textContent = 'Stop scan';
  updateScan({
    percent: 0,
    gib_read: 0,
    gib_total: device.size_bytes / GIB,
    mib_per_s: 0,
    elapsed_secs: 0,
  });
  setScanMode('running');
  try {
    const scan = await invoke('scan_device', { node: device.device_node });
    let info = null;
    const infoPath = device.mount_point || device.device_node;
    try {
      info = await invoke('inspect', { path: infoPath });
    } catch (error) {
      info = null;
    }
    if (!info) {
      info = {
        profile_line: scan.media_line || deviceMediaFallback(device),
        headline: 'Read-only. Nothing on the disk was changed.',
        notes: [],
      };
    }
    renderResults(scan, info);
    show('screen-results');
  } catch (error) {
    setScanMode('confirm');
    showError($('scan-error'), error);
  }
});

function deviceMediaFallback(device) {
  return device.displayMeta || metaLine(device);
}

$('btn-scan-stop').addEventListener('click', async () => {
  $('btn-scan-stop').disabled = true;
  $('btn-scan-stop').textContent = 'Stopping...';
  try {
    await invoke('scan_cancel');
  } catch (error) {
    console.error(error);
  }
});

loadDevices();

function pathFromDialog(picked) {
  if (!picked) return '';
  if (typeof picked === 'string') return picked;
  if (typeof picked.path === 'string') return picked.path;
  return String(picked);
}

async function pickPath(directory) {
  const picked = await invoke('plugin:dialog|open', {
    options: {
      directory,
      multiple: false,
      title: directory ? 'Choose a folder on the drive' : 'Choose a disk image',
    },
  });
  return pathFromDialog(picked);
}

// A disk image check reports no progress, so the screen shows that it is busy.
function openReading(path) {
  $('scan-icon').replaceChildren(icon('image'));
  $('scan-name').textContent = baseName(path);
  $('scan-meta').textContent = parentDir(path);
  $('scan-error').hidden = true;
  gridCells($('read-grid'));
  setScanMode('reading');
  show('screen-scan');
}

$('btn-check-image').addEventListener('click', async () => {
  $('home-error').hidden = true;
  try {
    const path = await pickPath(false);
    if (!path) return;
    state.path = path;
    state.kind = 'file';
    state.device = null;
    openReading(path);
    const [scan, info] = await Promise.all([
      invoke('check', { path }),
      invoke('inspect', { path }),
    ]);
    renderResults(scan, info);
    show('screen-results');
  } catch (error) {
    show('screen-home');
    showError($('home-error'), error);
  }
});

// Erase asks for a folder, then for the path typed out, before anything is written.
async function chooseFolderToErase(errorEl) {
  errorEl.hidden = true;
  try {
    const path = await pickPath(true);
    if (!path) return;
    state.path = path;
    state.kind = 'dir';
    state.device = null;
    openErase();
  } catch (error) {
    showError(errorEl, error);
  }
}

$('btn-erase-free').addEventListener('click', () => {
  chooseFolderToErase($('home-error'));
});

$('btn-results-erase').addEventListener('click', () => {
  chooseFolderToErase($('results-error'));
});

async function openErase() {
  $('plan-summary').textContent = 'Working out how much there is to erase...';
  $('erase-target').textContent = state.path;
  $('erase-confirm').value = '';
  updateMatch();
  $('erase-error').hidden = true;
  $('erase-running').hidden = true;
  $('erase-setup').hidden = false;
  $('btn-erase-back').hidden = false;
  show('screen-erase');
  try {
    const plan = await invoke('erase_plan', { path: state.path });
    $('plan-summary').textContent = plan.summary;
  } catch (error) {
    $('plan-summary').textContent = '';
    showError($('erase-error'), error);
  }
}

// Results

function setVerdict(tone, iconName, title, detail) {
  const banner = $('verdict');
  banner.classList.remove('good', 'found');
  if (tone) banner.classList.add(tone);
  $('verdict-icon').replaceChildren(icon(iconName));
  $('verdict-title').textContent = title;
  $('verdict-detail').textContent = detail;
}

function renderChips(categories) {
  const chips = $('verdict-chips');
  chips.replaceChildren();
  for (const category of categories || []) {
    chips.append(el('li', '', `${category.count.toLocaleString()} ${category.label}`));
  }
  chips.hidden = chips.childElementCount === 0;
}

function renderResults(scan, info) {
  if (scan.canceled) {
    setVerdict(
      '',
      'stop',
      'Scan stopped early',
      'This is only the part that was read. It is not a result for the whole disk.',
    );
  } else if (scan.hits === 0) {
    setVerdict('good', 'check', 'Nothing recoverable found', scan.verdict);
  } else {
    const noun = scan.hits === 1 ? 'item' : 'items';
    const listed = (scan.hits_by_category || []).length > 0;
    setVerdict(
      'found',
      'alert',
      `About ${scan.hits.toLocaleString()} ${noun} could be brought back`,
      // The chips below list the same counts, so the sentence only repeats them.
      listed ? 'Anyone with free recovery software could find these.' : scan.verdict,
    );
  }
  renderChips(scan.hits_by_category);

  renderInspect($('results-profile-card'), info);

  const counts = [scan.blocks_structured, scan.blocks_random, scan.blocks_fill, scan.blocks_empty];
  const total = counts.reduce((sum, n) => sum + n, 0);
  BLOCK_CLASSES.forEach((name, i) => {
    $(`share-${name}`).textContent = shareText(counts[i], total);
    $(`blocks-${name}`).textContent =
      `${counts[i].toLocaleString()} ${counts[i] === 1 ? 'block' : 'blocks'}`;
  });
  paintGrid($('result-grid'), counts);

  const label = state.kind === 'device' && state.device && state.device.displayName
    ? state.device.displayName
    : scan.source;
  $('results-meta').textContent =
    `Read ${formatAmount(scan.gib_scanned)} of ${label}. Nothing was changed.`;

  const eraseNote = $('results-erase-note');
  const eraseButton = $('btn-results-erase');
  $('results-error').hidden = true;
  eraseNote.hidden = false;
  if (state.kind === 'file') {
    eraseButton.hidden = true;
    eraseNote.textContent =
      'This is a disk image. Erasing it would not change the drive it was copied from. To overwrite free space, start over and choose a folder on the drive.';
  } else {
    eraseButton.hidden = false;
    eraseButton.classList.toggle('primary', scan.hits > 0);
    eraseNote.textContent =
      'To overwrite free space, choose a folder on the drive. gone does not erase a whole disk.';
  }
}

// Erase

function updateMatch() {
  const typed = $('erase-confirm').value.trim();
  const matches = typed !== '' && typed === state.path;
  const hint = $('erase-match');
  $('btn-erase').disabled = !matches;
  hint.classList.toggle('ok', matches);
  if (matches) {
    hint.replaceChildren(icon('check'), el('span', '', 'The path matches.'));
  } else {
    hint.textContent = typed === '' ? '' : 'Keep typing. The path has to match exactly.';
  }
}

$('erase-confirm').addEventListener('input', updateMatch);

function updateErase(p) {
  $('erase-percent').textContent = formatPercent(p.percent);
  fillGrid($('erase-grid'), p.percent);
  $('erase-written').textContent =
    `${p.gib_written.toFixed(1)} GiB of ${p.gib_planned.toFixed(1)} GiB`;
  $('erase-speed').textContent = formatSpeed(p.mib_per_s);
  $('erase-left').textContent = timeLeft(p.percent, p.elapsed_secs);
}

listen('erase-progress', (event) => updateErase(event.payload));

function setEraseRunning(running) {
  $('erase-setup').hidden = running;
  $('btn-erase-back').hidden = running;
  $('erase-running').hidden = !running;
}

$('btn-erase').addEventListener('click', async () => {
  const confirm = $('erase-confirm').value.trim();
  $('erase-error').hidden = true;
  $('btn-erase-cancel').disabled = false;
  $('btn-erase-cancel').textContent = 'Stop early';
  updateErase({ percent: 0, gib_written: 0, gib_planned: 0, mib_per_s: 0, elapsed_secs: 0 });
  setEraseRunning(true);
  try {
    const result = await invoke('erase_run', { path: state.path, confirm });
    state.bytesWritten = result.bytes_written;
    state.canceled = result.canceled;
    $('done-banner').classList.toggle('good', !result.canceled);
    $('done-icon').replaceChildren(icon(result.canceled ? 'stop' : 'check'));
    $('done-title').textContent = result.canceled ? 'Stopped early' : 'All done';
    $('done-summary').textContent = result.summary;
    resetVerify();
    show('screen-done');
  } catch (error) {
    setEraseRunning(false);
    showError($('erase-error'), error);
  }
});

$('btn-erase-cancel').addEventListener('click', async () => {
  $('btn-erase-cancel').disabled = true;
  $('btn-erase-cancel').textContent = 'Stopping...';
  try {
    await invoke('erase_cancel');
  } catch (error) {
    // Setting the flag is best-effort; the run also ends on its own.
    console.error(error);
  }
});

// Verify: sign a certificate, show where it landed

function resetVerify() {
  $('verify-prompt').hidden = false;
  $('verify-result').hidden = true;
  $('verify-error').hidden = true;
}

$('btn-done-verify').addEventListener('click', async () => {
  const button = $('btn-done-verify');
  setBusy(button, 'Verifying...');
  $('verify-error').hidden = true;
  $('verify-result').hidden = true;
  try {
    const view = await invoke('verify_run', {
      path: state.path,
      bytesWritten: state.bytesWritten,
      canceled: state.canceled,
    });
    $('verify-sentence').textContent = view.outcome_sentence;
    const signature = $('verify-signature');
    signature.classList.toggle('bad', !view.signature_ok);
    signature.replaceChildren(
      icon(view.signature_ok ? 'check' : 'alert'),
      el(
        'span',
        '',
        view.signature_ok
          ? 'Signature checks out. Any later edit to the JSON is detectable.'
          : 'The certificate signature did not verify.',
      ),
    );
    const list = $('verify-files');
    list.replaceChildren();
    for (const p of view.cert_paths) {
      const item = document.createElement('li');
      const copy = document.createElement('span');
      copy.append(el('span', 'file-name', baseName(p)), el('span', 'file-path', p));
      item.append(icon('doc'), copy);
      list.append(item);
    }
    $('verify-prompt').hidden = true;
    $('verify-result').hidden = false;
  } catch (error) {
    showError($('verify-error'), error);
  } finally {
    clearBusy(button);
  }
});

// Navigation back to Home

for (const id of ['btn-results-back', 'btn-erase-back', 'btn-done-restart']) {
  $(id).addEventListener('click', () => {
    resetVerify();
    state.device = null;
    state.kind = 'missing';
    state.path = '';
    show('screen-home');
    loadDevices();
  });
}

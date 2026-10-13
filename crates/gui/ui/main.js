'use strict';

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);

const state = { path: '' };

const SCREENS = ['screen-home', 'screen-results', 'screen-erase', 'screen-done'];

function show(id) {
  for (const screen of SCREENS) {
    $(screen).hidden = screen !== id;
  }
  window.scrollTo(0, 0);
}

function showError(el, error) {
  el.textContent = String(error);
  el.hidden = false;
}

function fillNotes(listEl, notes) {
  listEl.replaceChildren();
  for (const text of notes) {
    const li = document.createElement('li');
    li.textContent = text;
    listEl.append(li);
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

// Home

const homePath = $('home-path');

homePath.addEventListener('input', () => {
  const hasPath = homePath.value.trim().length > 0;
  $('btn-check').disabled = !hasPath;
  $('btn-inspect').disabled = !hasPath;
});

$('btn-inspect').addEventListener('click', async () => {
  const button = $('btn-inspect');
  setBusy(button, 'Inspecting...');
  $('home-error').hidden = true;
  try {
    const view = await invoke('inspect', { path: homePath.value.trim() });
    renderInspect($('inspect-card'), view);
  } catch (error) {
    showError($('home-error'), error);
  } finally {
    clearBusy(button);
  }
});

$('btn-check').addEventListener('click', async () => {
  const path = homePath.value.trim();
  state.path = path;
  const button = $('btn-check');
  setBusy(button, 'Checking...');
  $('home-error').hidden = true;
  try {
    const [scan, info] = await Promise.all([
      invoke('check', { path }),
      invoke('inspect', { path }),
    ]);
    renderResults(scan, info);
    show('screen-results');
  } catch (error) {
    showError($('home-error'), error);
  } finally {
    clearBusy(button);
  }
});

// Results

function renderResults(scan, info) {
  const banner = $('verdict-banner');
  banner.classList.remove('good', 'bad');
  if (scan.hits === 0) {
    banner.classList.add('good');
    $('verdict-title').textContent = 'Good news: nothing recoverable found.';
  } else {
    banner.classList.add('bad');
    const noun = scan.hits === 1 ? 'item' : 'items';
    $('verdict-title').textContent = `About ${scan.hits} ${noun} could be brought back`;
  }
  $('verdict-detail').textContent = scan.verdict;

  renderInspect($('results-profile-card'), info);

  $('blocks-empty').textContent = scan.blocks_empty.toLocaleString();
  $('blocks-fill').textContent = scan.blocks_fill.toLocaleString();
  $('blocks-random').textContent = scan.blocks_random.toLocaleString();
  $('blocks-structured').textContent = scan.blocks_structured.toLocaleString();
  $('scan-meta').textContent =
    `Scanned ${scan.gib_scanned.toFixed(1)} GiB of ${scan.source}. Read-only: no files were changed.`;
}

// Erase

$('btn-to-erase').addEventListener('click', async () => {
  $('plan-summary').textContent = 'Working out how much there is to erase...';
  $('erase-target').textContent = state.path;
  $('erase-confirm').value = '';
  $('btn-erase').disabled = true;
  $('erase-error').hidden = true;
  $('erase-running').hidden = true;
  $('erase-actions').hidden = false;
  show('screen-erase');
  try {
    const plan = await invoke('erase_plan', { path: state.path });
    $('plan-summary').textContent = plan.summary;
  } catch (error) {
    $('plan-summary').textContent = '';
    showError($('erase-error'), error);
  }
});

$('erase-confirm').addEventListener('input', () => {
  $('btn-erase').disabled = $('erase-confirm').value.trim() !== state.path;
});

function updateEraseBar(p) {
  $('erase-bar-fill').style.width = `${Math.min(100, p.percent)}%`;
  $('erase-status').textContent =
    `${p.percent.toFixed(1)}%, ${p.gib_written.toFixed(1)} GiB of ${p.gib_planned.toFixed(1)} GiB written, ` +
    `${p.mib_per_s.toFixed(0)} MiB/s, ${p.elapsed_secs.toFixed(0)} s elapsed`;
}

listen('erase-progress', (event) => updateEraseBar(event.payload));

$('btn-erase').addEventListener('click', async () => {
  const confirm = $('erase-confirm').value.trim();
  $('erase-actions').hidden = true;
  $('erase-running').hidden = false;
  $('erase-error').hidden = true;
  $('btn-erase-cancel').disabled = false;
  updateEraseBar({ percent: 0, gib_written: 0, gib_planned: 0, mib_per_s: 0, elapsed_secs: 0 });
  try {
    const summary = await invoke('erase_run', { path: state.path, confirm });
    $('done-title').textContent = summary.includes('Stopped early') ? 'Stopped early' : 'All done';
    $('done-summary').textContent = summary;
    show('screen-done');
  } catch (error) {
    $('erase-running').hidden = true;
    $('erase-actions').hidden = false;
    showError($('erase-error'), error);
  }
});

$('btn-erase-cancel').addEventListener('click', async () => {
  $('btn-erase-cancel').disabled = true;
  try {
    await invoke('erase_cancel');
  } catch (error) {
    // Setting the flag is best-effort; the run also ends on its own.
    console.error(error);
  }
});

// Verify: rescan, sign a certificate, show where it landed

$('btn-done-verify').addEventListener('click', async () => {
  const button = $('btn-done-verify');
  setBusy(button, 'Verifying...');
  $('verify-error').hidden = true;
  $('verify-result').hidden = true;
  try {
    const view = await invoke('verify_run', { path: state.path });
    $('verify-sentence').textContent = view.outcome_sentence;
    $('verify-signature').textContent = view.signature_ok
      ? 'Signature checks out. Any later edit to the JSON is detectable.'
      : 'WARNING: the certificate signature did not verify.';
    const list = $('verify-files');
    list.replaceChildren();
    for (const p of view.cert_paths) {
      const li = document.createElement('li');
      li.textContent = p;
      list.append(li);
    }
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
    $('inspect-card').hidden = true;
    $('verify-result').hidden = true;
    $('verify-error').hidden = true;
    homePath.value = '';
    homePath.dispatchEvent(new Event('input'));
    show('screen-home');
  });
}

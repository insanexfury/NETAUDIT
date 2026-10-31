const statusRegion = document.getElementById('portal-status');
const panels = Array.from(document.querySelectorAll('.portal-form'));

document.querySelectorAll('[data-panel]').forEach((button) => {
  button.addEventListener('click', () => {
    panels.forEach((panel) => panel.classList.toggle('hidden', panel.id !== button.dataset.panel));
    document.querySelectorAll('[data-panel]').forEach((tab) => tab.classList.toggle('active', tab === button));
    statusRegion.textContent = '';
  });
});

document.getElementById('login-panel').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = Object.fromEntries(new FormData(event.currentTarget));
  await submit('/auth/login', form, 'Signing in…', (result) => {
    sessionStorage.setItem('netaudit-csrf', result.csrf_token);
    window.location.assign('/workspace');
  });
});

document.getElementById('register-panel').addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = Object.fromEntries(new FormData(event.currentTarget));
  await submit('/auth/register-company', form, 'Registering company…', (result) => {
    sessionStorage.setItem('netaudit-csrf', result.csrf_token);
    const reveal = document.getElementById('joining-code-result');
    reveal.replaceChildren();
    const heading = document.createElement('strong');
    heading.textContent = 'Save this one-time company joining code:';
    const code = document.createElement('code');
    code.textContent = result.joining_code;
    reveal.append(heading, code);
    panels.forEach((panel) => panel.classList.add('hidden'));
    statusRegion.textContent = `Company "${result.company.name}" is ready. You are signed in as its ADMIN.`;
    reveal.classList.remove('hidden');
  });
});

document.getElementById('join-panel').addEventListener('submit', async (event) => {
  event.preventDefault();
  const formElement = event.currentTarget;
  const form = Object.fromEntries(new FormData(formElement));
  await submit('/auth/join-company', form, 'Sending access request…', () => {
    statusRegion.textContent = 'Your request is pending company administrator approval. You can sign in after approval.';
    formElement.reset();
  });
});

async function submit(path, body, progress, onSuccess) {
  statusRegion.textContent = progress;
  statusRegion.classList.remove('error');
  try {
    const response = await fetch(path, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(readDetail(result.detail) || `Request failed (${response.status}).`);
    onSuccess(result);
  } catch (error) {
    statusRegion.textContent = error.message || 'The request could not be completed.';
    statusRegion.classList.add('error');
  }
}

function readDetail(detail) {
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map((entry) => entry.msg).filter(Boolean).join(' ');
  return '';
}

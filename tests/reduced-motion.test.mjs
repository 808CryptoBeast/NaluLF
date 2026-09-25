// Regression guard for the "Reduced-motion mode" roadmap item.
//
// Two layers, mirroring theme.js's existing pattern for the color-theme
// system: (1) a global CSS kill-switch in base.css — every animation/
// transition is shrunk to near-zero duration and played once (the standard
// web.dev/prefers-reduced-motion technique, applied broadly rather than
// auditing every keyframe/transition across this app's ~10 CSS files one by
// one), with loading spinners exempted so they don't read as "stuck" during
// a multi-second fetch — and (2) motion.js, which applies that same
// treatment via a body.reduce-motion class driven by either the OS-level
// prefers-reduced-motion setting OR an explicit in-app Settings choice
// (System/Reduce/Full) — the "mode" part: a user whose OS prefers reduced
// motion can still explicitly choose Full for this app specifically, and
// vice versa for a user without (or not wanting to touch) the OS setting.
import { withPage, freshSignup, makeSuite, assert } from './helpers.mjs';

const suite = makeSuite('Reduced Motion');

suite.register('Default: no OS preference, no saved choice — motion is full, preference reads "system"', async () => {
  await withPage(async (page, { pageErrors }) => {
    const state = await page.evaluate(() => ({
      hasClass: document.body.classList.contains('reduce-motion'),
      pref: window.getMotionPreference(),
    }));
    assert(!state.hasClass, 'expected no reduce-motion class by default');
    assert(state.pref === 'system', `expected the default preference to read "system", got "${state.pref}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('setMotionPreference("reduce") applies the class and actually shrinks animation-duration to near-zero', async () => {
  await withPage(async (page, { pageErrors }) => {
    const after = await page.evaluate(() => {
      window.setMotionPreference('reduce');
      const el = document.createElement('div');
      el.style.animation = 'spin 1s linear infinite';
      document.body.appendChild(el);
      const dur = getComputedStyle(el).animationDuration;
      el.remove();
      return { hasClass: document.body.classList.contains('reduce-motion'), stored: localStorage.getItem('naluxrp_reduce_motion'), animDuration: dur };
    });
    assert(after.hasClass, 'expected the reduce-motion class to be applied');
    assert(after.stored === 'reduce', `expected localStorage to persist "reduce", got "${after.stored}"`);
    assert(parseFloat(after.animDuration) < 0.001, `expected animation-duration to be shrunk to near-zero, got "${after.animDuration}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Loading spinners are exempted from the animation-duration shrink so they keep spinning, not freeze', async () => {
  await withPage(async (page, { pageErrors }) => {
    const spinnerDuration = await page.evaluate(() => {
      window.setMotionPreference('reduce');
      const el = document.createElement('div');
      el.className = 'spinner';
      document.body.appendChild(el);
      const dur = getComputedStyle(el).animationDuration;
      const iter = getComputedStyle(el).animationIterationCount;
      el.remove();
      return { dur, iter };
    });
    assert(parseFloat(spinnerDuration.dur) > 0.1, `expected .spinner to keep a real animation duration under reduce-motion, got "${spinnerDuration.dur}"`);
    assert(spinnerDuration.iter === 'infinite', `expected .spinner to keep looping infinitely under reduce-motion, got "${spinnerDuration.iter}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('setMotionPreference("full") removes the class even with no OS preference involved', async () => {
  await withPage(async (page, { pageErrors }) => {
    const after = await page.evaluate(() => {
      window.setMotionPreference('reduce');
      window.setMotionPreference('full');
      return { hasClass: document.body.classList.contains('reduce-motion'), stored: localStorage.getItem('naluxrp_reduce_motion') };
    });
    assert(!after.hasClass, 'expected the reduce-motion class to be removed after choosing Full');
    assert(after.stored === 'full', `expected localStorage to persist "full", got "${after.stored}"`);
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('"system" preference follows the OS-level prefers-reduced-motion setting on boot, and an explicit "full" choice overrides it', async () => {
  await withPage(async (page, { pageErrors }) => {
    await page.evaluate(() => window.setMotionPreference('system'));
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.reload({ waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(400);

    const followed = await page.evaluate(() => ({
      hasClass: document.body.classList.contains('reduce-motion'),
      pref: window.getMotionPreference(),
    }));
    assert(followed.hasClass, 'expected the OS-level reduced-motion preference to be picked up automatically when the saved preference is "system"');
    assert(followed.pref === 'system', `expected the preference to still read "system", got "${followed.pref}"`);

    const overridden = await page.evaluate(() => {
      window.setMotionPreference('full');
      return document.body.classList.contains('reduce-motion');
    });
    assert(!overridden, 'expected an explicit "full" choice to override the OS-level reduced-motion preference');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

suite.register('Settings panel: the Motion segmented control renders System/Reduce/Full, reflects the current choice, and clicking a button applies it live', async () => {
  await withPage(async (page, { pageErrors }) => {
    const ok = await freshSignup(page, { name: 'Motion Test', email: 'motiontest@test.com', domain: 'motiontest' });
    assert(ok, 'signup failed');
    await page.evaluate(() => window.showProfile());
    await page.waitForTimeout(300);
    await page.evaluate(() => window.tourSkip && window.tourSkip());
    await page.evaluate(() => window.switchProfileTab('settings'));
    await page.waitForTimeout(300);

    const buttons = await page.evaluate(() => [...document.querySelectorAll('.settings-seg-btn')]
      .filter(b => /Follow system|Reduce|Full/.test(b.textContent))
      .map(b => b.textContent.trim()));
    assert(buttons.includes('Follow system') && buttons.includes('Reduce') && buttons.includes('Full'), `expected all 3 motion options to render, got: ${JSON.stringify(buttons)}`);

    const clicked = await page.evaluate(() => {
      const btn = [...document.querySelectorAll('.settings-seg-btn')].find(b => b.textContent.trim() === 'Reduce');
      btn.click();
      return {
        bodyHasClass: document.body.classList.contains('reduce-motion'),
        reduceIsActive: [...document.querySelectorAll('.settings-seg-btn')].find(b => b.textContent.trim() === 'Reduce')?.classList.contains('active'),
      };
    });
    assert(clicked.bodyHasClass, 'expected clicking "Reduce" to apply the class to <body> immediately');
    assert(clicked.reduceIsActive, 'expected the "Reduce" button to be marked active after clicking it');
    assert(pageErrors.length === 0, `expected zero page errors, got: ${JSON.stringify(pageErrors)}`);
  });
});

const { pass, fail, total } = await suite.run();
process.exitCode = fail ? 1 : 0;
export { pass, fail, total };

/**
 * Quiz sound helper — plays WAV from /static/sounds/
 * Respects enableSound flag (from server settings).
 */
(function (global) {
  const BASE = '/static/sounds/';
  const FILES = {
    correct: 'correct.wav',
    wrong: 'wrong.wav',
    timeout: 'timeout.wav',
    click: 'click.wav',
    start: 'start.wav',
    finish: 'finish.wav'
  };

  let enabled = false;
  const cache = {};

  function setEnabled(v) {
    enabled = !!v;
  }

  function isEnabled() {
    return enabled;
  }

  function preload() {
    Object.keys(FILES).forEach(function (key) {
      if (cache[key]) return;
      try {
        const a = new Audio(BASE + FILES[key]);
        a.preload = 'auto';
        a.volume = 0.55;
        cache[key] = a;
      } catch (e) {}
    });
  }

  function play(name) {
    if (!enabled) return;
    try {
      let a = cache[name];
      if (!a) {
        a = new Audio(BASE + (FILES[name] || name));
        a.volume = 0.55;
        cache[name] = a;
      }
      a.currentTime = 0;
      const p = a.play();
      if (p && typeof p.catch === 'function') {
        p.catch(function () {});
      }
    } catch (e) {}
  }

  global.QuizSound = {
    setEnabled: setEnabled,
    isEnabled: isEnabled,
    preload: preload,
    play: play
  };
})(window);

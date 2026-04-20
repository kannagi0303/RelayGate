(function () {
  function closestActionTrigger(element) {
    return element && element.closest('[rg-post]');
  }

  function applyFeedback(target, payload) {
    if (!target || !payload) {
      return;
    }

    target.textContent = payload.message || '';
    target.dataset.feedbackLevel = payload.level || (payload.ok === false ? 'error' : 'success');
    if (target.dataset.feedbackLevel === 'error') {
      target.style.color = '#8f3b2f';
    } else {
      target.style.color = '';
    }
  }

  function parseResponseHtml(html) {
    var template = document.createElement('template');
    template.innerHTML = html;
    return template;
  }

  function applySwap(target, swap, html) {
    if (!target) {
      return;
    }

    if (swap === 'outerHTML') {
      target.outerHTML = html;
      return;
    }

    target.innerHTML = html;
  }

  function applyOutOfBandSwaps(template) {
    var nodes = template.content.querySelectorAll('[rg-swap-oob]');
    nodes.forEach(function (node) {
      var swap = node.getAttribute('rg-swap-oob') || 'innerHTML';
      var id = node.id;
      if (!id) {
        node.remove();
        return;
      }

      var current = document.getElementById(id);
      if (!current) {
        node.remove();
        return;
      }

      if (swap === 'outerHTML') {
        current.outerHTML = node.outerHTML.replace(/\s+rg-swap-oob="[^"]*"/, '');
      } else {
        current.innerHTML = node.innerHTML;
      }

      node.remove();
    });
  }

  function serializeActionForm(trigger) {
    if (trigger.tagName === 'FORM') {
      return new URLSearchParams(new FormData(trigger));
    }

    var form = trigger.closest('form');
    if (form) {
      return new URLSearchParams(new FormData(form));
    }

    return new URLSearchParams();
  }

  function requestAction(trigger) {
    var url = trigger.getAttribute('rg-post');
    if (!url) {
      return;
    }

    var targetSelector = trigger.getAttribute('rg-target');
    var swap = trigger.getAttribute('rg-swap') || 'innerHTML';
    var target = targetSelector ? document.querySelector(targetSelector) : null;
    var body = serializeActionForm(trigger);

    fetch(url, {
      method: 'POST',
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
        'Accept': 'application/json, text/html;q=0.9, */*;q=0.8',
      },
      body: body.toString(),
    })
      .then(function (response) {
        var contentType = response.headers.get('content-type') || '';
        if (contentType.indexOf('application/json') >= 0) {
          return response.json().then(function (payload) {
            return { kind: 'json', payload: payload };
          });
        }

        return response.text().then(function (html) {
          return { kind: 'html', payload: html };
        });
      })
      .then(function (result) {
        if (result.kind === 'json') {
          if (target) {
            applyFeedback(target, result.payload);
          }
          return;
        }

        var template = parseResponseHtml(result.payload);
        applyOutOfBandSwaps(template);
        var remainingHtml = template.innerHTML.trim();

        if (target && remainingHtml) {
          applySwap(target, swap, remainingHtml);
          processActionNode(target);
        }

        if (document.body) {
          processActionNode(document.body);
        }
      });
  }

  function bindActionElement(element) {
    if (!element || element.dataset.relaygateActionBound === '1') {
      return;
    }

    if (element.tagName === 'FORM') {
      element.addEventListener('submit', function (event) {
        event.preventDefault();
        requestAction(element);
      });
    } else {
      element.addEventListener('click', function (event) {
        var trigger = closestActionTrigger(event.target);
        if (!trigger || trigger !== element) {
          return;
        }

        if (
          trigger.tagName === 'BUTTON' &&
          trigger.type === 'submit' &&
          trigger.closest('form')
        ) {
          return;
        }

        event.preventDefault();
        requestAction(trigger);
      });
    }

    element.dataset.relaygateActionBound = '1';
  }

  function processActionNode(root) {
    if (!root) {
      return;
    }

    if (root.matches && root.matches('[rg-post]')) {
      bindActionElement(root);
    }

    root.querySelectorAll('[rg-post]').forEach(bindActionElement);
  }

  window.RelayGateActions = {
    process: processActionNode,
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      processActionNode(document.body);
    });
  } else {
    processActionNode(document.body);
  }
})();
